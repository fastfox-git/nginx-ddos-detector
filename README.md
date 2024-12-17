# Nginx DDoS Detector (L7)

Наше решение не предназначено для защиты от самих атак, но оно эффективно обнаруживает сайты, на которые ведется DDoS атака на уровне L7 (HTTP флуд).

Скрипт обнаружит сайт на который ведется атака и заблокирует его. Также если атака на сайт прекращена - скрипт автоматически его разблокирует.

По умолчанию есть поддержка Telegram уведомлений.

## Как установить

1. В директории /root создайте папку ddosdetector и загрузите в нее файлы. Если вы хотите использовать другую директорию, то измените путь до папки со скриптом в параметре `FILE_PATH` (без слэша на конце).
2. Создайте задание от root в планировщике. К сожалению, в Cron нет возможности указать запуск команды меньше, чем каждую минуту, поэтому, например, для запуска скрипта каждые 15 секунд укажите команду:

```
php /root/ddosdetector/script.php && sleep 15 && php /root/ddosdetector/script.php && sleep 15 && php /root/ddosdetector/script.php && sleep 15 && php /root/ddosdetector/script.php
```

> [!NOTE]
> При этом выполнение команды в планировщике укажите каждую минуту */1.

> [!IMPORTANT]
> Обратите внимание! Из коробки скрипт будет идеально работать с панелью управления Ispmanager. Если на вашем сервере другая структура для Nginx, то измените пути в параметрах `PATH_VHOSTS`, `PATH_VHOSTS_RESOURCES` и `PATH_VHOSTS_INCLUDES`.

**Важные пути:**

`/etc/nginx/vhosts/` - в этом каталоге скрипт ищет логин владельца сайта

`/etc/nginx/vhosts-resources/` - внутри директории папки сайтов пользователей, в которые скрипт будет помещать конфиг для блокировки.

`/etc/nginx/vhosts-includes/` - в эту директорию скрипт копирует файл logs.conf для включения логов всех сайтов.

Последние 2 пути должны быть включены через include в каждом конфиге сайта Nginx.

## Параметры

| Параметр | Описание |
| --- | --- |
| `BASEDIR` | путь до папки новых логов. При замене также требуется изменить в файле blackhole.conf и logs.conf |
| `CONNECT` | число коннектов Nginx, при которых начинается поиск сайта для блокировки |
| `BAN_SIZE` | размер указывается в байтах. Если размер лога сайта больше, чем задано в параметре, то сайт блокируется |
| `UNBAN_SIZE` | размер указывается в байтах. Если размер лога сайта меньше, чем задано в параметре, то сайт будет разблокирован |
| `FILE_PATH` | путь до каталога, где расположен скрипт (без слэша на конце) |
| `MIN_ATTACK_TIME` | минимальное время в секундах, на которое будет заблокирован сайт, даже если атака на него прекращена |
| `DEBUG` | принимает true/false. Включает и отключает логирование действий скрипта в файл ddos.log |
| `WHITE_LIST` | Белый список. В переменной $WHITE_LIST вы можете указать белый список сайтов, которые не будут блокироваться скриптом. По умолчанию в список добавлен localhost, в лог localhost.access.log собираются запросы с тех сайтов, которые не существуют на веб-сервере, но А-записи сайта ведут на Ваш сервер. Поэтому мы рекомендуем на сервере для сайта по умолчанию выдавать ошибку 403 со своим шаблоном страницы, например, то, что сайт не добавлен на сервере. |

> [!NOTE]
> Значения для блокировки и разблокировки - разные, т.к. в нашем случае мы блокируем сайт с ошибкой 444, и не все запросы учитываются в логе. Но, например, если блокировать сайт с ошибкой 403, то значения переменных UNBAN_SIZE и BAN_SIZE можно сделать примерно одинаковыми.