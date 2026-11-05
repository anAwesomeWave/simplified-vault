package core

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type cachedSecret struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

func (s *Service) invalidate(ctx context.Context, id string) {
	if s.cache == nil {
		return
	}
	cacheCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	// A failed invalidation cannot grant access: every read authorizes in PostgreSQL.
	_ = s.cache.Del(cacheCtx, "secret:"+id).Err()
}

func (s *Service) readText(ctx context.Context, tx pgx.Tx, item *secret) (string, error) {
	if s.cache != nil {
		cacheCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		data, err := s.cache.Get(cacheCtx, "secret:"+item.ID).Bytes()
		cancel()
		if err == nil {
			var cached cachedSecret
			if json.Unmarshal(data, &cached) == nil {
				if text, err := s.cipher.Decrypt(item.ID, cached.Ciphertext, cached.Nonce); err == nil {
					return text, nil
				}
			}
			s.invalidate(ctx, item.ID)
		}
	}
	var cached cachedSecret
	if err := tx.QueryRow(ctx, `SELECT ciphertext,nonce FROM secrets WHERE id=$1`, item.ID).Scan(&cached.Ciphertext, &cached.Nonce); err != nil {
		return "", err
	}
	text, err := s.cipher.Decrypt(item.ID, cached.Ciphertext, cached.Nonce)
	if err != nil {
		return "", err
	}
	if s.cache == nil {
		return text, nil
	}
	data, err := json.Marshal(cached)
	if err != nil {
		return "", err
	}
	ttl := time.Until(item.ExpiresAt)
	if ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	if ttl > 0 {
		cacheCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		defer cancel()
		_ = s.cache.Set(cacheCtx, "secret:"+item.ID, data, ttl).Err()
	}
	return text, nil
}
