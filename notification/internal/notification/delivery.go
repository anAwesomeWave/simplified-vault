package notification

import "context"

// Consumer читает события из брокера и передаёт их в UseCase
type Consumer interface {
	// Run читает очередь до отмены ctx, переподключаясь к брокеру при обрывах.
	// После отмены ctx дожидается обработки уже полученных сообщений и возвращает nil
	Run(ctx context.Context) error
	// Ready сообщает, что consumer подключён к брокеру и получает сообщения
	Ready() bool
}
