<?php

/**
 * DDoS Detector for Nginx/Apache
 *
 * @see https://fastfox.pro/
 *
 * @copyright Copyright (c) FastFox LLC
 * @license https://github.com/fastfox-git/nginx-ddos-detector/blob/main/LICENSE
 */

// Путь до папки новых логов. При замене также требуется изменить в файле blackhole.conf и logs.conf
const BASEDIR = '/ngx/';

// Имя сервера для определения в уведомлениях
const SERVER = 'Сервер: FF-RU-ISP1';

// Число коннектов Nginx при которых начинается поиск сайта для блокировки
const CONNECT = 5000;

// Указывается в байтах. Если размер лога больше указанного параметра, то сайт блокируется
const BAN_SIZE = 1242880;

// Указывается в байтах. Если размер лога меньше указанного параметра, то сайт будет разблокирован
const UNBAN_SIZE = 80800;

// Минимальное время в секундах на которое сайт будет заблокирован
const MIN_ATTACK_TIME = 119;

// Путь до папки со скриптом
const FILE_PATH = '/root/ddosdetector';

// Путь до виртуальных хостов. В этом каталоге скрипт ищет логин владельца сайта
const PATH_VHOSTS = '/etc/nginx/vhosts/';

// Путь до ресурсов виртуальных хостов. Внутри директории папки сайтов пользователей, в которые скрипт будет помещать конфиг для блокировки.
const PATH_VHOSTS_RESOURCES = '/etc/nginx/vhosts-resources/';

// В эту директорию скрипт копирует файл logs.conf для включения логов всех сайтов.
const PATH_VHOSTS_INCLUDES = '/etc/nginx/vhosts-includes/';

// Принимает true/false. Включает и отключает логирование действий скрипта в файл ddos.log
const DEBUG = true;

// Белый список сайтов
$WHITE_LIST = array('localhost', 'site.ru');

// Telegram Nofications Settings
// Bot token
const TG_BOT_TOKEN = ''; // For example 5128034826:AEAn0u0XKZCUrFwf_ZWknUUhdNsLjtXUQOA
const TG_CHAT_ID = ''; // For example -1001332541951
 

// Security
if (count(array_intersect([' ', '', '/'], [BASEDIR, FILE_PATH]))) {
    log_ddos('Ошибка в константах');
    return -1;
}

// Go WORK

$starttime = microtime(true);

$bannedSitesContent = file_get_contents(FILE_PATH . '/bannedSites.txt');
if (!$bannedSitesContent) {
    $bannedSitesContent = "[]";
}
$bannedSites = json_decode($bannedSitesContent, true);
$connections = `netstat -ant | grep -E ':80|:443' | wc -l`;
//unban
$unbanned = 0;
foreach ($bannedSites as $file => $time) {

    if (filesize(BASEDIR . $file . '.access.log') < UNBAN_SIZE
        && (microtime(true) - $time > MIN_ATTACK_TIME)) {

            $text = "🟢 <b>Атака на сайт прекращена</b>\n";
            $text .= "Сайт " . $file . " разблокирован";
            sendMessage(urlencode($text));

            unlink(PATH_VHOSTS_RESOURCES . $file . '/blackhole.conf');
            unset($bannedSites[$file]);

            log_ddos(' - unban: ' . $file . ' size: ' . filesize(BASEDIR . $file . '.access.log'));
            $unbanned++;
            exec('truncate -s 0 ' . BASEDIR . $file . '.access.log');


    } else {
        log_ddos(' > ' . $file . ' Не можем разбанить. забанен на протяжении ' .
            (microtime(true) - $time) . 'сек. Размер лога: : ' .
            filesize(BASEDIR . $file . '.access.log'));

        if (!is_file(FILE_PATH . '/attack_started!')) {
            exec('truncate -s 0 ' . BASEDIR . $file . '.access.log');
        }
    }


}
if ($unbanned > 0) {
    `service nginx reload`;
    if (!is_file(FILE_PATH . '/attack_started!') && count($bannedSites) == 0) {
        exec('rm -f '.PATH_VHOSTS_INCLUDES.'logs.conf');

        if (!in_array(BASEDIR, ['', '/'])) {
            exec('find ' . BASEDIR . ' -type f -exec rm -f {}\;');
        }
    }

}


//ban if lots of connections

log_ddos('! connections: ' . trim($connections));
if ($connections >= CONNECT) {

    if (!is_file(FILE_PATH . '/attack_started!')) {

        $text = "‼️ <b>Началась атака</b>\n";
        $text .= "Соединений: " . trim($connections) . "\n";
        $text .= "Определяем на кого идет атака";
        sendMessage(urlencode($text));

        exec('touch ' . FILE_PATH . '/attack_started!');
        if (!in_array(BASEDIR, ['', '/'])) {
            exec('find ' . BASEDIR . ' -type f -exec truncate --size 0 {} \;');
        }
        copy(FILE_PATH . '/logs.conf',
            PATH_VHOSTS_INCLUDES.'logs.conf');
        `service nginx reload`;

    } else {
        $banned = 0;
        $files = scandir(BASEDIR);
        $accessFiles = [];
        foreach ($files as $file) {
            if (preg_match('/([^"]+)access\.log/', $file)) {
                $accessFiles[] = $file;
            }
        }
        foreach ($accessFiles as $file) {
            if (filesize(BASEDIR . $file) >= BAN_SIZE) {
                $siteDir = explode(".access.log", $file)[0];

                if (!in_array($siteDir, $WHITE_LIST)) {
                    if (in_array($siteDir, array_keys($bannedSites))) {
                        if (!is_file(PATH_VHOSTS_RESOURCES . $siteDir . '/blackhole.conf')) {
                            log_ddos('recopy ban file to ' . $siteDir);
                            copy(FILE_PATH . '/blackhole.conf',
                                PATH_VHOSTS_RESOURCES
                                . $siteDir . '/blackhole.conf');
                            `service nginx reload`;
                        }
                    } else {

                        if(PATH_VHOSTS){
                        $userSiteFile = exec('find '.PATH_VHOSTS.'*/ -name ' . $siteDir . '.conf');
                        $userSiteFileParts = explode('/', $userSiteFile);
                        $user = $userSiteFileParts[count($userSiteFileParts) - 2];
                        }else{
                            $user = 'nouser';
                        }

                        if (is_dir(PATH_VHOSTS_RESOURCES . $siteDir)) {

                            $text = "🔍️ <b>Цель обнаружена</b>\n";
                            $text .= "Блокируем сайт: " . $siteDir;
                            sendMessage(urlencode($text));

                            log_ddos( ' + ban: ' . $siteDir . ' size: ' . filesize(BASEDIR
                                    . $file) . " uzver: " . $user);
                            copy(FILE_PATH . '/blackhole.conf',
                                PATH_VHOSTS_RESOURCES
                                . $siteDir . '/blackhole.conf');

                            $bannedSites[$siteDir] = microtime(true);
                            $banned++;
                        } else {
                            $text = "❓️ <b>Требуется проверка</b>\n";
                            $text .= "Атакуют неизвестный ресурс: " . $siteDir;
                            sendMessage(urlencode($text));

                            file_put_contents(FILE_PATH . '/error_ddos.log', date("Y-m-d H:i:s") . ' cannot ban: ' .
                                $siteDir . ' size: ' . filesize
                                (BASEDIR . $file) . " uzver: " . $user->name . "\n", FILE_APPEND);

                        }
                    }

                }

            }
        }

        if ($banned > 0) {

            `service nginx reload`;

        }
        if (!in_array(BASEDIR, ['', '/'])) {
            exec('find ' . BASEDIR . ' -type f -exec truncate --size 0 {} \;');
        }

    }

} else {
    if (is_file(FILE_PATH . '/attack_started!')) {

        if (!in_array(BASEDIR, ['', '/'])) {
            exec('find ' . BASEDIR . ' -type f -exec truncate --size 0 {} \;');
        }
        if (!in_array(FILE_PATH, ['', '/'])) {
            exec('rm -f ' . FILE_PATH . '/attack_started!');
        }


        if (count($bannedSites) == 0) {
            exec('rm -f '.PATH_VHOSTS_INCLUDES.'logs.conf');
            `service nginx reload`;

            if (!in_array(BASEDIR, ['', '/'])) {
                exec('find ' . BASEDIR . ' -type f -exec rm -f {}\;');
            }

        }
        $text = "✅ <b>Атака отбита</b>\n";
        $text .= "Соединений на данный момент: " . trim($connections);
        sendMessage(urlencode($text));
    }


}

file_put_contents(FILE_PATH . '/bannedSites.txt', json_encode($bannedSites));

$endtime = microtime(true);
$timediff = $endtime - $starttime;
log_ddos('Время выполнения скрипта: ' . $timediff . "\n");

function sendMessage($text)
{
    if(TG_BOT_TOKEN && TG_CHAT_ID){
        $ch = curl_init("https://api.telegram.org/bot".TG_BOT_TOKEN."/sendMessage?chat_id=".TG_CHAT_ID."&parse_mode=html&text=" . $text . urlencode("\n\n" . SERVER));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        echo curl_exec($ch);
        echo "\n";
    
        curl_close($ch);
        return $ch;
    }
}

function log_ddos($msg)
{
    if(DEBUG){
        file_put_contents(FILE_PATH . '/ddos.log', date("Y-m-d H:i:s") . ' ' . $msg . "\n", FILE_APPEND);
    }
}

