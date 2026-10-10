# wscan — TODO

Принцип: **только наш движок**, без зависимостей от внешних проектов (`bin/nuclei`, `bin/nmap`).
Формат шаблонов nuclei и NSE-скрипты — это библиотека проверок, а не движок.

## Сделано
- [x] Убрано всё внешнее исполнение (nuclei/nmap бинари); сканы и NSE только на нативном движке.
- [x] Каталог оценивает совместимость нативно (без проверки наличия внешних бинарей).
- [x] OOB/interactsh: свой OAST-коллаборатор (HTTP-callback), подстановка `{{interactsh-url}}`, матчеры читают коллбэк из env; без коллбэка — нет находки (без ложняков).
- [x] Фикс ложняка `compare_versions("", "<X")` → false (пустая/нечисловая версия не сравнивается).
- [x] Профиль скорости запуска в настройках (всё сразу: RPS/параллельность/таймаут/повторы).
- [x] Карточка находки показывает impact/remediation/классификацию (CVSS/CVE/CWE).
- [x] `raw`-запросы + `variables` + генераторы dsl (rand_*).
- [x] `payloads` + `attack` (фаззинг): batteringram/pitchfork/clusterbomb, inline+файловые списки, лимит комбинаций, рендеринг значений (FQDN/RDN/date_time). Три режима покрыты тестами.
- [x] Нативные протоколы `tcp`/`network` (+267), `dns` (+29), `ssl` (+32): сырой TCP (hex/text inputs, binary-матчер), DNS (A/AAAA/CNAME/MX/NS/TXT, dig-подобный answer), TLS-сертификат (issuer/subject/SAN/срок, json-экстрактор). Покрыто тестами.
- [x] Совместимость nuclei-шаблонов: **67.3% (9466/14072)**.

- [x] R1 безвредные поля, R2 json-экстрактор (мини-jq), R3 матчеры на уровне шаблона. → **68.42%**
- [x] R4 Workflows → **70.00% (9835/14050)**
- [x] R5 Extractor-only (без matchers, только extractors) → **71.44% (10037/14050)**
- [x] R6 XPath + мелкие HTTP-поля; R7 DSL hmac/aes/gadget/jarm/rand_ip; R8 SSL tls_version/cipher → **71.54% (10052/14050)**
- [x] R9 Парсер: `tcp`/`network` `port` как список (`"6379,6380"`, не только int), `info.reference` как скаляр (не только список) → **71.66% (10068/14050)**. Это чинило все 17 настоящих ошибок парсинга YAML в каталоге; `cmd/compatcount` при этом путал их с намеренными scope-отказами (self-contained/local-audit) под общей меткой «parse» — разбакечено.
- [x] R10 `flow` — встроенный JS-движок (`github.com/dop251/goja`, чистый Go, без внешнего процесса — та же схема, что уже даёт `gopher-lua` для NSE). Скрипт `flow:` решает, какие блоки `http`/`tcp`/`network`/`dns`/`ssl` запускать и в каком порядке (`http(1) && http(2)`, циклы, `if`), вызывая обратно наши же `execHTTPRequest`/`runTCP`/`runDNS`/`runSSL`. Передача переменных между шагами — `template["x"]`/`template.x` и `set("x", y)` через один и тот же `vars` (DynamicObject, без копий). `code:`/`javascript:` по-прежнему запрещены/не реализованы — если `flow`-шаблон их использует, он остаётся несовместимым на этапе парсинга (не падает в середине скана). → **79.31% (11143/14050)**, +1075 шаблонов. Смоук-тест (прогон реального `flow:`-скрипта через goja с заглушками вместо сети) показал 1067/1075 (99.3%) реально исполняются, не только парсятся; 8 падают на `iterate()`, «богатом» объекте-ответе (`http(1).body...`) и `stop()` — в бэклог.
- [x] R11 `code:` — единственное исключение из «только наш движок»: по явному запросу владельца проекта (приоритет — переносимость/минимум зависимостей, а не жёсткий запрет внешних интерпретаторов). Выполняется через реальный `python3`/`ruby`/`bash`/... на машине сканера: исходник в temp-файл, таймаут через `context.WithTimeout`, на unix — отдельная process group + `SIGKILL` всей группы по таймауту (иначе потомок вроде `sleep` в shell-скрипте держит stdout-pipe и блокирует `Cmd.Wait()` дольше таймаута — поймано тестом), `Cmd.WaitDelay` как бэкстоп. Доступность в каталоге — честная: смотрим `exec.LookPath` по списку `engine:` шаблона, недоступно = «интерпретатор не найден», а не блокирующая заглушка. Запуск отдельно гейтится per-project флагом `AllowCodeExec` (по умолчанию `false`, в БД); включение в TUI только через экран-предупреждение (`code-exec-confirm`), выключение — без подтверждения. `brute.delay`/`brute.threads` для NSE brute-скриптов теперь тоже выводятся автоматически из RPS/параллельности скана (`nse.DefaultBruteArgs`), а не из дефолтов самого nmap (20 потоков, 0 задержки). На этой машине: 33/34 `code:`-шаблонов в библиотеке совместимы (есть `python3`/`sh`/`bash`), 1 блокируется честно — нет `ruby`.
- [x] R12 Metasploit auxiliary/scanner → без зависимости от внешнего софта (отклонён вариант с RPC к `msfrpcd`). Модули Ruby не интерпретируются: логика переносится статическим codegen'ом `library/tools/gen_msf_scanner.py` в наши `tcp:`-шаблоны (`library/nuclei-templates/custom/msf-scanner/`). Из 643 scanner-модулей кандидаты — ~90 с mixin'ами только `Tcp`/`Udp` (без HttpClient/SMB/…); login/brute/DoS/file-write отсекаются. На текущем прогоне: **30 ported / 62 skipped** (отчёт `GENERATED.md`). Три mixin-проба (clamav VERSION-only, rocketmq, sip OPTIONS) заданы overrides в генераторе. HttpClient (329) и SMB/прочие протоколы — вне scope. `exploits/*` не начаты. Перегенерация: `python3 library/tools/gen_msf_scanner.py && python3 library/tools/gen_categories.py`.

- [x] R13 `javascript:` — встроенный goja + SDK `require("nuclei/…")`: net, bytes, ssh, redis, mysql, postgres, smb (go-smb2), mssql (probe). Globals: Export/ExportAs, isPortOpen/isUDPPortOpen. Payloads/attack как у HTTP. → **все 131** `javascript/` в каталоге доступны; +142 к available (11555→11697). Stub: ldap/vnc/oracle/rsync/rdp/smtp/fs.

## Бэклог (по убыванию выхлопа)
- [x] Flow: `http(N)` возвращает объект-ответ (`.body`/`.status_code`/…, truthy при матче), `http_last_response`, `stop()` — остаток смоук-теста R10 закрыт. `iterate()` / именованные `http("id")` — ранее. Scope: при скане конкретного порта шаблон не уходит на другой порт (`resolveURL` + `@Host`).
- [ ] `javascript:` добивка stub-модулей (ldap/vnc/oracle/rsync/rdp/smtp/fs) и полный TDS для mssql — по мере нужды
- [ ] DNS-based OOB (нужна DNS-инфраструктура: authoritative + делегированный домен)
- [ ] Полные commons-collections gadgets (сейчас URLDNS fallback)
- [ ] XPath 2.0 (`matches()` и т.п.) — сейчас только XPath 1.0
- [ ] NSE: полноценный LPeg (сейчас stub с metamethods — `re.lua`/часть http-скриптов грузятся частично; match не работает). Без настоящего LPeg скрипты на `require "re"`/`lpeg` остаются ограниченными.

## Вне scope (по правилу/сложности)
- [x] `code` — реализовано (R11): реальный внешний интерпретатор на машине сканера, per-project opt-in (`AllowCodeExec`, выключен по умолчанию) + обязательное предупреждение в TUI перед включением. Из вне-scope ушло.
- [x] `flow` (~1280) — реализовано на встроенном JS (R10, goja); из вне-scope ушло, см. бэклог/сделано
- [x] `self-contained` (~1690) — выполняются на сканере, не на цели (намеренно исключены; вычищены из выбора проектов)
- [ ] `file` / локальный аудит ОС (~630)
- [ ] `headless` (~222) — браузер / DOM; критичное уже покрыто HTTP-шаблонами
- [ ] `unsafe`, `fuzzing` (DAST)

## Известные проблемы / полировка
- [x] Большая параллельность «укладывает» слабые цели (роутер): adaptive per-host concurrency + backoff на reset/timeout; discovery soft-throttle на connection reset.
- [x] Шумные info-находки NSE (`http-google-malware: No API key`, `http-title: Site doesn't have a title`) — отфильтрованы через `OutputIsNoise`.
- [x] TUI layout-тест `TestViewFillsTerminalAndKeepsFooterAfterResize` — панели через `renderPanel` (контент truncate/pad до высоты, рамка всегда снизу).
- [x] Пакет `toolruntime` убран: `LocalTemplateReason` / `NetworkTemplateReason` перенесены в `internal/template`.
- [x] Stale `inventory_resets.through_run` после purge/передобавления хоста — порты не показывались на столе.
- [x] Raw-аннотации nuclei (`@timeout`/`@once`/`@Host`/`@tls-sni`), `{{BaseURL}}:port`, Host/Hostname как в nuclei, `duration` для time-based.
- [x] Исчерпание ephemeral-портов при concurrency 128 / RPS 0: worker pool + MaxConnsPerHost + soft RPS + backoff на `cannot assign requested address`.
