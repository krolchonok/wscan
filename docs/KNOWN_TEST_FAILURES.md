# Ограничения первого релиза

Полный локальный прогон `CGO_ENABLED=0 go test ./...` выявил ошибки в internal/engine:

- TestSSHDefaultLoginsWrongPasswordIsQuietNotAnError
- TestCVE202334039InitUpdatePayloadReadsRealKeys
- TestMSFGeneratedRedisServerInfo
- TestUpstreamSMB2ServerTimeReadsNegotiationLog
- TestUpstreamSMBSigningReadsSecurityMode
- TestCVE202348795RunsEndToEndWithoutCrashing

SSH-тесты получают overflow reading version string, Redis — unexpected prefix H,
SMB-тесты не получают ожидаемые находки. Причины пока не установлены.
Остальные пакеты прошли локальный прогон. Неиспользуемый импорт в cmd/payload
исправлен в вынесенных исходниках; пакет повторно проверен.

Сборка приложения и проверка переноса отделены от этих функциональных тестов.
Релиз предварительный. CI запускает полный набор тестов и записывает результат
в описание предварительного релиза; сбой тестов не блокирует его публикацию.
Ни один тест не отключён. Стабильный релиз требует устранения этих сбоев.
