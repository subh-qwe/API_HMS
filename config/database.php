<?php

return [
    'default' => env('DB_CONNECTION', 'mysql'),

    'connections' => [
        'mysql' => [
            'driver' => 'mysql',
            'host' => env('DB_HOST', 'gondola.proxy.rlwy.net'),
            'port' => env('DB_PORT', '55772'),
            'database' => env('DB_DATABASE', 'RMS'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', 'pFCsVCAvyEfJhPdybGrcrTHuvuBriMtU'),
            'unix_socket' => env('DB_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'engine' => null,
        ],
    ],
];
