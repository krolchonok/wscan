# Удалённый сбор BloodHound CE

В проекте открой взаимодействия → AD — учётки и первоначальный доступ →
**BloodHound CE: удалённый сбор домена → ZIP**.

- `h`: IP/DNS контроллера; `d`: DNS-имя домена.
- `c`: сохранённая доменная учётка типа password или ntlm-hash.
- `l`: LDAPS/636 (по умолчанию) либо LDAP/389, без автоматического fallback.
- `n`: лимит объектов домена и членов каждой группы, 1–50000 (по умолчанию 5000).
- `Enter`: запуск; `g`: задача, прогресс и журнал; Esc в окне запуска отменяет сбор.

Весь сбор выполняется внутри wscan на машине оператора. Используется один DC
и naming context выбранного домена. Не выполняются обращения к рабочим
станциям, переходы по LDAP referrals, загрузка файлов или запуск команд на
целях. DNS-имя DC разрешается системным DNS; для VPN настрой доменный DNS
на машине wscan. Вступление машины оператора в домен не требуется для NTLM.

Первый профиль собирает Users, Computers, Groups, Domains, OU, GPO, Containers;
SID/GUID, членство, primary group, containment, GPO links и доменные доверия.
Большие группы читаются через member range retrieval. Неразрешённые члены
(включая foreign security principals без доступного объекта), лимиты,
LDAP-ошибки и referrals отмечаются как частичный результат. При неверном
домене, отказе входа или отсутствии SID домена ZIP не создаётся.

**Пока не собираются:** ACL, AD CS, SYSVOL, машинные сессии/локальные права,
реестр, разрешённые связи делегирования и SID history. Это доменный профиль,
не полный эквивалент SharpHound. Поддержка Kerberos/ccache, LDAP signing и
channel binding — следующие этапы; конфигурации AD, запрещающие текущий
NTLM-вход, вернут ошибку. Используется существующая политика LDAP-клиента
wscan: сертификаты частной PKI не проверяются по системному trust store.

Экспорт: `exports/bloodhound/bloodhound-ce-*.zip` относительно каталога данных
приложения. ZIP содержит только семь AD JSON файлов со схемой v6 и маской
методов Group/Trusts/Container/ObjectProps (673). Итоги, неполнота и список
несобранных методов записываются рядом в `*.zip.summary.json`, вне ZIP.
Пароль, NTLM-хеш и ответы аутентификации в экспорт не попадают.

ZIP загружается в BloodHound CE через Administration → File Ingest. Формат
сопоставлен с официальными incoming models и fixtures; живой импорт и
сравнение графа в реальном домене пока не проверены. Legacy не поддерживается
этим профилем.

Источники схемы:
- https://bloodhound.specterops.io/integrations/bloodhound-api/json-formats
- https://github.com/SpecterOps/BloodHound/blob/main/packages/go/ein/incoming_models.go
- https://github.com/SpecterOps/BloodHound/blob/main/packages/go/chow/ingest/ingest.go
