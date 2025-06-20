<?php

require_once __DIR__.'/../vendor/autoload.php';

require_once __DIR__ . '/../app/helpers.php';

(new Laravel\Lumen\Bootstrap\LoadEnvironmentVariables(
    dirname(__DIR__)
))->bootstrap();

date_default_timezone_set(env('APP_TIMEZONE', 'UTC'));

/*
|--------------------------------------------------------------------------
| Create The Application
|--------------------------------------------------------------------------
|
| Here we will load the environment and create the application instance
| that serves as the central piece of this framework. We'll use this
| application as an "IoC" container and router for this framework.
|
*/

$app = new Laravel\Lumen\Application(
    dirname(__DIR__)
);

// Adding the Mail facade
$app->withFacades(true, [
    Illuminate\Support\Facades\Mail::class => 'Mail',
]);


$app->withFacades();

$app->withEloquent();


/*
|--------------------------------------------------------------------------
| Register Container Bindings
|--------------------------------------------------------------------------
|
| Now we will register a few bindings in the service container. We will
| register the exception handler and the console kernel. You may add
| your own bindings here if you like or you can make another file.
|
*/

$app->singleton(
    Illuminate\Contracts\Debug\ExceptionHandler::class,
    App\Exceptions\Handler::class
);

$app->singleton(
    Illuminate\Contracts\Console\Kernel::class,
    App\Console\Kernel::class
);


/*
|--------------------------------------------------------------------------
| Register Config Files
|--------------------------------------------------------------------------
|
| Now we will register the "app" configuration file. If the file exists in
| your configuration directory it will be loaded; otherwise, we'll load
| the default version. You may register other files below as needed.
|
*/

$app->configure('app');

$app->configure('mail');

$app->configure('database');

$app->configure('auth');

$app->configure('jwt');

/*
|--------------------------------------------------------------------------
| Register Middleware
|--------------------------------------------------------------------------
|
| Next, we will register the middleware with the application. These can
| be global middleware that run before and after each request into a
| route or middleware that'll be assigned to some specific routes.
|
*/


$app->middleware([
    App\Http\Middleware\CorsMiddleware::class
]);

$app->routeMiddleware([
        'auth' => App\Http\Middleware\Authenticate::class,
        'jwt.auth' => App\Http\Middleware\JwtMiddleware::class,
        'admin.role' => App\Http\Middleware\AdminRoleMiddleware::class,
     ]);

/*
|--------------------------------------------------------------------------
| Register Service Providers
|--------------------------------------------------------------------------
|
| Here we will register all of the application's service providers which
| are used to bind services into the container. Service providers are
| totally optional, so you are not required to uncomment this line.
|
*/

$app->register(Flipbox\LumenGenerator\LumenGeneratorServiceProvider::class);
$app->register(App\Providers\AppServiceProvider::class);
$app->register(App\Providers\AuthServiceProvider::class);
$app->register(App\Providers\EventServiceProvider::class);
//Registering the mail service provider here
$app->register(Illuminate\Mail\MailServiceProvider::class);
$app->register(App\Providers\CloudinaryServiceProvider::class);

// Regestring the JWT service provider
$app->register(Tymon\JWTAuth\Providers\LumenServiceProvider::class);
$app->alias('JWTAuth', Tymon\JWTAuth\Facades\JWTAuth::class);
$app->alias('JWTFactory', Tymon\JWTAuth\Facades\JWTFactory::class);
$app->register(App\Providers\AuthServiceProvider::class);


// Register DomPDF Service Provider
$app->register(\Barryvdh\DomPDF\ServiceProvider::class);

// Create an alias for the PDF facade
$app->configure('dompdf');
class_alias(\Barryvdh\DomPDF\Facade\Pdf::class, 'PDF');

// Make sure storage directory is accessible
$app->useStoragePath(env('STORAGE_PATH', base_path() . '/storage'));


// Configure mail settings
$app->configure('services');

/*
|--------------------------------------------------------------------------
| Load The Application Routes
|--------------------------------------------------------------------------
|
| Next we will include the routes file so that they can all be added to
| the application. This will provide all of the URLs the application
| can respond to, as well as the controllers that may handle them.
|
*/

$app->router->group([
    'namespace' => 'App\Http\Controllers',
], function ($router) {
    require __DIR__.'/../routes/web.php';
});

return $app;
