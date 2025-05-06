<?php
namespace Illuminate\Contracts\Container {
use Closure;
use Psr\Container\ContainerInterface;
interface Container extends ContainerInterface
{
    public function bound($abstract);
    public function alias($abstract, $alias);
    public function tag($abstracts, $tags);
    public function tagged($tag);
    public function bind($abstract, $concrete = null, $shared = false);
    public function bindMethod($method, $callback);
    public function bindIf($abstract, $concrete = null, $shared = false);
    public function singleton($abstract, $concrete = null);
    public function singletonIf($abstract, $concrete = null);
    public function scoped($abstract, $concrete = null);
    public function scopedIf($abstract, $concrete = null);
    public function extend($abstract, Closure $closure);
    public function instance($abstract, $instance);
    public function addContextualBinding($concrete, $abstract, $implementation);
    public function when($concrete);
    public function factory($abstract);
    public function flush();
    public function make($abstract, array $parameters = []);
    public function call($callback, array $parameters = [], $defaultMethod = null);
    public function resolved($abstract);
    public function beforeResolving($abstract, ?Closure $callback = null);
    public function resolving($abstract, ?Closure $callback = null);
    public function afterResolving($abstract, ?Closure $callback = null);
}
}

namespace Illuminate\Contracts\Container {
interface ContextualBindingBuilder
{
    public function needs($abstract);
    public function give($implementation);
    public function giveTagged($tag);
    public function giveConfig($key, $default = null);
}
}

namespace Illuminate\Contracts\Foundation {
use Illuminate\Contracts\Container\Container;
interface Application extends Container
{
    public function version();
    public function basePath($path = '');
    public function bootstrapPath($path = '');
    public function configPath($path = '');
    public function databasePath($path = '');
    public function langPath($path = '');
    public function publicPath($path = '');
    public function resourcePath($path = '');
    public function storagePath($path = '');
    public function environment(...$environments);
    public function runningInConsole();
    public function runningUnitTests();
    public function hasDebugModeEnabled();
    public function maintenanceMode();
    public function isDownForMaintenance();
    public function registerConfiguredProviders();
    public function register($provider, $force = false);
    public function registerDeferredProvider($provider, $service = null);
    public function resolveProvider($provider);
    public function boot();
    public function booting($callback);
    public function booted($callback);
    public function bootstrapWith(array $bootstrappers);
    public function getLocale();
    public function getNamespace();
    public function getProviders($provider);
    public function hasBeenBootstrapped();
    public function loadDeferredProviders();
    public function setLocale($locale);
    public function shouldSkipMiddleware();
    public function terminating($callback);
    public function terminate();
}
}

namespace Illuminate\Contracts\Bus {
interface Dispatcher
{
    public function dispatch($command);
    public function dispatchSync($command, $handler = null);
    public function dispatchNow($command, $handler = null);
    public function hasCommandHandler($command);
    public function getCommandHandler($command);
    public function pipeThrough(array $pipes);
    public function map(array $map);
}
}

namespace Illuminate\Contracts\Bus {
interface QueueingDispatcher extends Dispatcher
{
    public function findBatch(string $batchId);
    public function batch($jobs);
    public function dispatchToQueue($command);
}
}

namespace Illuminate\Contracts\Pipeline {
use Closure;
interface Pipeline
{
    public function send($traveler);
    public function through($stops);
    public function via($method);
    public function then(Closure $destination);
}
}

namespace Illuminate\Contracts\Support {
interface Renderable
{
    public function render();
}
}

namespace Illuminate\Contracts\Debug {
use Throwable;
interface ExceptionHandler
{
    public function report(Throwable $e);
    public function shouldReport(Throwable $e);
    public function render($request, Throwable $e);
    public function renderForConsole($output, Throwable $e);
}
}

namespace Illuminate\Contracts\Config {
interface Repository
{
    public function has($key);
    public function get($key, $default = null);
    public function all();
    public function set($key, $value = null);
    public function prepend($key, $value);
    public function push($key, $value);
}
}

namespace Illuminate\Contracts\Events {
interface Dispatcher
{
    public function listen($events, $listener = null);
    public function hasListeners($eventName);
    public function subscribe($subscriber);
    public function until($event, $payload = []);
    public function dispatch($event, $payload = [], $halt = false);
    public function push($event, $payload = []);
    public function flush($event);
    public function forget($event);
    public function forgetPushed();
}
}

namespace Illuminate\Contracts\Support {
interface Arrayable
{
    public function toArray();
}
}

namespace Illuminate\Contracts\Support {
interface Jsonable
{
    public function toJson($options = 0);
}
}

namespace Illuminate\Contracts\Cookie {
interface Factory
{
    public function make($name, $value, $minutes = 0, $path = null, $domain = null, $secure = null, $httpOnly = true, $raw = false, $sameSite = null);
    public function forever($name, $value, $path = null, $domain = null, $secure = null, $httpOnly = true, $raw = false, $sameSite = null);
    public function forget($name, $path = null, $domain = null);
}
}

namespace Illuminate\Contracts\Cookie {
interface QueueingFactory extends Factory
{
    public function queue(...$parameters);
    public function unqueue($name, $path = null);
    public function getQueuedCookies();
}
}

namespace Illuminate\Contracts\Encryption {
interface Encrypter
{
    public function encrypt($value, $serialize = true);
    public function decrypt($payload, $unserialize = true);
    public function getKey();
}
}

namespace Illuminate\Contracts\Queue {
interface QueueableEntity
{
    public function getQueueableId();
    public function getQueueableRelations();
    public function getQueueableConnection();
}
}

namespace Illuminate\Contracts\Routing {
interface Registrar
{
    public function get($uri, $action);
    public function post($uri, $action);
    public function put($uri, $action);
    public function delete($uri, $action);
    public function patch($uri, $action);
    public function options($uri, $action);
    public function match($methods, $uri, $action);
    public function resource($name, $controller, array $options = []);
    public function group(array $attributes, $routes);
    public function substituteBindings($route);
    public function substituteImplicitBindings($route);
}
}

namespace Illuminate\Contracts\Routing {
interface ResponseFactory
{
    public function make($content = '', $status = 200, array $headers = []);
    public function noContent($status = 204, array $headers = []);
    public function view($view, $data = [], $status = 200, array $headers = []);
    public function json($data = [], $status = 200, array $headers = [], $options = 0);
    public function jsonp($callback, $data = [], $status = 200, array $headers = [], $options = 0);
    public function stream($callback, $status = 200, array $headers = []);
    public function streamDownload($callback, $name = null, array $headers = [], $disposition = 'attachment');
    public function download($file, $name = null, array $headers = [], $disposition = 'attachment');
    public function file($file, array $headers = []);
    public function redirectTo($path, $status = 302, $headers = [], $secure = null);
    public function redirectToRoute($route, $parameters = [], $status = 302, $headers = []);
    public function redirectToAction($action, $parameters = [], $status = 302, $headers = []);
    public function redirectGuest($path, $status = 302, $headers = [], $secure = null);
    public function redirectToIntended($default = '/', $status = 302, $headers = [], $secure = null);
}
}

namespace Illuminate\Contracts\Routing {
interface UrlGenerator
{
    public function current();
    public function previous($fallback = false);
    public function to($path, $extra = [], $secure = null);
    public function secure($path, $parameters = []);
    public function asset($path, $secure = null);
    public function route($name, $parameters = [], $absolute = true);
    public function action($action, $parameters = [], $absolute = true);
    public function getRootControllerNamespace();
    public function setRootControllerNamespace($rootNamespace);
}
}

namespace Illuminate\Contracts\Routing {
interface UrlRoutable
{
    public function getRouteKey();
    public function getRouteKeyName();
    public function resolveRouteBinding($value, $field = null);
    public function resolveChildRouteBinding($childType, $value, $field);
}
}

namespace Illuminate\Contracts\Validation {
interface ValidatesWhenResolved
{
    public function validateResolved();
}
}

namespace Illuminate\Contracts\View {
interface Factory
{
    public function exists($view);
    public function file($path, $data = [], $mergeData = []);
    public function make($view, $data = [], $mergeData = []);
    public function share($key, $value = null);
    public function composer($views, $callback);
    public function creator($views, $callback);
    public function addNamespace($namespace, $hints);
    public function replaceNamespace($namespace, $hints);
}
}

namespace Illuminate\Contracts\Support {
interface MessageProvider
{
    public function getMessageBag();
}
}

namespace Illuminate\Contracts\Support {
use Countable;
interface MessageBag extends Arrayable, Countable
{
    public function keys();
    public function add($key, $message);
    public function merge($messages);
    public function has($key);
    public function first($key = null, $format = null);
    public function get($key, $format = null);
    public function all($format = null);
    public function forget($key);
    public function getMessages();
    public function getFormat();
    public function setFormat($format = ':message');
    public function isEmpty();
    public function isNotEmpty();
}
}

namespace Illuminate\Contracts\View {
use Illuminate\Contracts\Support\Renderable;
interface View extends Renderable
{
    public function name();
    public function with($key, $value = null);
    public function getData();
}
}

namespace Illuminate\Contracts\Http {
interface Kernel
{
    public function bootstrap();
    public function handle($request);
    public function terminate($request, $response);
    public function getApplication();
}
}

namespace Illuminate\Contracts\Auth {
interface Guard
{
    public function check();
    public function guest();
    public function user();
    public function id();
    public function validate(array $credentials = []);
    public function hasUser();
    public function setUser(Authenticatable $user);
}
}

namespace Illuminate\Contracts\Auth {
interface StatefulGuard extends Guard
{
    public function attempt(array $credentials = [], $remember = false);
    public function once(array $credentials = []);
    public function login(Authenticatable $user, $remember = false);
    public function loginUsingId($id, $remember = false);
    public function onceUsingId($id);
    public function viaRemember();
    public function logout();
}
}

namespace Illuminate\Contracts\Auth\Access {
interface Gate
{
    public function has($ability);
    public function define($ability, $callback);
    public function resource($name, $class, ?array $abilities = null);
    public function policy($class, $policy);
    public function before(callable $callback);
    public function after(callable $callback);
    public function allows($ability, $arguments = []);
    public function denies($ability, $arguments = []);
    public function check($abilities, $arguments = []);
    public function any($abilities, $arguments = []);
    public function authorize($ability, $arguments = []);
    public function inspect($ability, $arguments = []);
    public function raw($ability, $arguments = []);
    public function getPolicyFor($class);
    public function forUser($user);
    public function abilities();
}
}

namespace Illuminate\Contracts\Hashing {
interface Hasher
{
    public function info($hashedValue);
    public function make($value, array $options = []);
    public function check($value, $hashedValue, array $options = []);
    public function needsRehash($hashedValue, array $options = []);
}
}

namespace Illuminate\Contracts\Auth {
interface UserProvider
{
    public function retrieveById($identifier);
    public function retrieveByToken($identifier, $token);
    public function updateRememberToken(Authenticatable $user, $token);
    public function retrieveByCredentials(array $credentials);
    public function validateCredentials(Authenticatable $user, array $credentials);
}
}

namespace Illuminate\Contracts\Pagination {
interface Paginator
{
    public function url($page);
    public function appends($key, $value = null);
    public function fragment($fragment = null);
    public function nextPageUrl();
    public function previousPageUrl();
    public function items();
    public function firstItem();
    public function lastItem();
    public function perPage();
    public function currentPage();
    public function hasPages();
    public function hasMorePages();
    public function path();
    public function isEmpty();
    public function isNotEmpty();
    public function render($view = null, $data = []);
}
}

namespace Illuminate\Auth {
use Closure;
use Illuminate\Contracts\Auth\Factory as FactoryContract;
use InvalidArgumentException;
class AuthManager implements FactoryContract
{
    use CreatesUserProviders;
    protected $app;
    protected $customCreators = [];
    protected $guards = [];
    protected $userResolver;
    public function __construct($app)
    {
        $this->app = $app;
        $this->userResolver = fn($guard = null) => $this->guard($guard)->user();
    }
    public function guard($name = null)
    {
        $name = $name ?: $this->getDefaultDriver();
        return $this->guards[$name] ?? $this->guards[$name] = $this->resolve($name);
    }
    protected function resolve($name)
    {
        $config = $this->getConfig($name);
        if (is_null($config)) {
            throw new InvalidArgumentException("Auth guard [{$name}] is not defined.");
        }
        if (isset($this->customCreators[$config['driver']])) {
            return $this->callCustomCreator($name, $config);
        }
        $driverMethod = 'create' . ucfirst($config['driver']) . 'Driver';
        if (method_exists($this, $driverMethod)) {
            return $this->{$driverMethod}($name, $config);
        }
        throw new InvalidArgumentException("Auth driver [{$config['driver']}] for guard [{$name}] is not defined.");
    }
    protected function callCustomCreator($name, array $config)
    {
        return $this->customCreators[$config['driver']]($this->app, $name, $config);
    }
    public function createSessionDriver($name, $config)
    {
        $provider = $this->createUserProvider($config['provider'] ?? null);
        $guard = new SessionGuard($name, $provider, $this->app['session.store']);
        if (method_exists($guard, 'setCookieJar')) {
            $guard->setCookieJar($this->app['cookie']);
        }
        if (method_exists($guard, 'setDispatcher')) {
            $guard->setDispatcher($this->app['events']);
        }
        if (method_exists($guard, 'setRequest')) {
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
        }
        if (isset($config['remember'])) {
            $guard->setRememberDuration($config['remember']);
        }
        return $guard;
    }
    public function createTokenDriver($name, $config)
    {
        $guard = new TokenGuard($this->createUserProvider($config['provider'] ?? null), $this->app['request'], $config['input_key'] ?? 'api_token', $config['storage_key'] ?? 'api_token', $config['hash'] ?? false);
        $this->app->refresh('request', $guard, 'setRequest');
        return $guard;
    }
    protected function getConfig($name)
    {
        return $this->app['config']["auth.guards.{$name}"];
    }
    public function getDefaultDriver()
    {
        return $this->app['config']['auth.defaults.guard'];
    }
    public function shouldUse($name)
    {
        $name = $name ?: $this->getDefaultDriver();
        $this->setDefaultDriver($name);
        $this->userResolver = fn($name = null) => $this->guard($name)->user();
    }
    public function setDefaultDriver($name)
    {
        $this->app['config']['auth.defaults.guard'] = $name;
    }
    public function viaRequest($driver, callable $callback)
    {
        return $this->extend($driver, function () use ($callback) {
            $guard = new RequestGuard($callback, $this->app['request'], $this->createUserProvider());
            $this->app->refresh('request', $guard, 'setRequest');
            return $guard;
        });
    }
    public function userResolver()
    {
        return $this->userResolver;
    }
    public function resolveUsersUsing(Closure $userResolver)
    {
        $this->userResolver = $userResolver;
        return $this;
    }
    public function extend($driver, Closure $callback)
    {
        $this->customCreators[$driver] = $callback;
        return $this;
    }
    public function provider($name, Closure $callback)
    {
        $this->customProviderCreators[$name] = $callback;
        return $this;
    }
    public function hasResolvedGuards()
    {
        return count($this->guards) > 0;
    }
    public function forgetGuards()
    {
        $this->guards = [];
        return $this;
    }
    public function setApplication($app)
    {
        $this->app = $app;
        return $this;
    }
    public function __call($method, $parameters)
    {
        return $this->guard()->{$method}(...$parameters);
    }
}
}

namespace Illuminate\Auth {
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\CurrentDeviceLogout;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\SupportsBasicAuth;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJar;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Support\Timebox;
use Illuminate\Support\Traits\Macroable;
use InvalidArgumentException;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
class SessionGuard implements StatefulGuard, SupportsBasicAuth
{
    use GuardHelpers, Macroable;
    public readonly string $name;
    protected $lastAttempted;
    protected $viaRemember = false;
    protected $rememberDuration = 576000;
    protected $session;
    protected $cookie;
    protected $request;
    protected $events;
    protected $timebox;
    protected $loggedOut = false;
    protected $recallAttempted = false;
    public function __construct($name, UserProvider $provider, Session $session, ?Request $request = null, ?Timebox $timebox = null)
    {
        $this->name = $name;
        $this->session = $session;
        $this->request = $request;
        $this->provider = $provider;
        $this->timebox = $timebox ?: new Timebox();
    }
    public function user()
    {
        if ($this->loggedOut) {
            return;
        }
        if (!is_null($this->user)) {
            return $this->user;
        }
        $id = $this->session->get($this->getName());
        if (!is_null($id) && $this->user = $this->provider->retrieveById($id)) {
            $this->fireAuthenticatedEvent($this->user);
        }
        if (is_null($this->user) && !is_null($recaller = $this->recaller())) {
            $this->user = $this->userFromRecaller($recaller);
            if ($this->user) {
                $this->updateSession($this->user->getAuthIdentifier());
                $this->fireLoginEvent($this->user, true);
            }
        }
        return $this->user;
    }
    protected function userFromRecaller($recaller)
    {
        if (!$recaller->valid() || $this->recallAttempted) {
            return;
        }
        $this->recallAttempted = true;
        $this->viaRemember = !is_null($user = $this->provider->retrieveByToken($recaller->id(), $recaller->token()));
        return $user;
    }
    protected function recaller()
    {
        if (is_null($this->request)) {
            return;
        }
        if ($recaller = $this->request->cookies->get($this->getRecallerName())) {
            return new Recaller($recaller);
        }
    }
    public function id()
    {
        if ($this->loggedOut) {
            return;
        }
        return $this->user() ? $this->user()->getAuthIdentifier() : $this->session->get($this->getName());
    }
    public function once(array $credentials = [])
    {
        $this->fireAttemptEvent($credentials);
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);
            return true;
        }
        return false;
    }
    public function onceUsingId($id)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);
            return $user;
        }
        return false;
    }
    public function validate(array $credentials = [])
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        return $this->hasValidCredentials($user, $credentials);
    }
    public function basic($field = 'email', $extraConditions = [])
    {
        if ($this->check()) {
            return;
        }
        if ($this->attemptBasic($this->getRequest(), $field, $extraConditions)) {
            return;
        }
        return $this->failedBasicResponse();
    }
    public function onceBasic($field = 'email', $extraConditions = [])
    {
        $credentials = $this->basicCredentials($this->getRequest(), $field);
        if (!$this->once(array_merge($credentials, $extraConditions))) {
            return $this->failedBasicResponse();
        }
    }
    protected function attemptBasic(Request $request, $field, $extraConditions = [])
    {
        if (!$request->getUser()) {
            return false;
        }
        return $this->attempt(array_merge($this->basicCredentials($request, $field), $extraConditions));
    }
    protected function basicCredentials(Request $request, $field)
    {
        return [$field => $request->getUser(), 'password' => $request->getPassword()];
    }
    protected function failedBasicResponse()
    {
        throw new UnauthorizedHttpException('Basic', 'Invalid credentials.');
    }
    public function attempt(array $credentials = [], $remember = false)
    {
        $this->fireAttemptEvent($credentials, $remember);
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);
            return true;
        }
        $this->fireFailedEvent($user, $credentials);
        return false;
    }
    public function attemptWhen(array $credentials = [], $callbacks = null, $remember = false)
    {
        $this->fireAttemptEvent($credentials, $remember);
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials) && $this->shouldLogin($callbacks, $user)) {
            $this->login($user, $remember);
            return true;
        }
        $this->fireFailedEvent($user, $credentials);
        return false;
    }
    protected function hasValidCredentials($user, $credentials)
    {
        return $this->timebox->call(function ($timebox) use ($user, $credentials) {
            $validated = !is_null($user) && $this->provider->validateCredentials($user, $credentials);
            if ($validated) {
                $timebox->returnEarly();
                $this->fireValidatedEvent($user);
            }
            return $validated;
        }, 200 * 1000);
    }
    protected function shouldLogin($callbacks, AuthenticatableContract $user)
    {
        foreach (Arr::wrap($callbacks) as $callback) {
            if (!$callback($user, $this)) {
                return false;
            }
        }
        return true;
    }
    public function loginUsingId($id, $remember = false)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);
            return $user;
        }
        return false;
    }
    public function login(AuthenticatableContract $user, $remember = false)
    {
        $this->updateSession($user->getAuthIdentifier());
        if ($remember) {
            $this->ensureRememberTokenIsSet($user);
            $this->queueRecallerCookie($user);
        }
        $this->fireLoginEvent($user, $remember);
        $this->setUser($user);
    }
    protected function updateSession($id)
    {
        $this->session->put($this->getName(), $id);
        $this->session->migrate(true);
    }
    protected function ensureRememberTokenIsSet(AuthenticatableContract $user)
    {
        if (empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }
    }
    protected function queueRecallerCookie(AuthenticatableContract $user)
    {
        $this->getCookieJar()->queue($this->createRecaller($user->getAuthIdentifier() . '|' . $user->getRememberToken() . '|' . $user->getAuthPassword()));
    }
    protected function createRecaller($value)
    {
        return $this->getCookieJar()->make($this->getRecallerName(), $value, $this->getRememberDuration());
    }
    public function logout()
    {
        $user = $this->user();
        $this->clearUserDataFromStorage();
        if (!is_null($this->user) && !empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }
        if (isset($this->events)) {
            $this->events->dispatch(new Logout($this->name, $user));
        }
        $this->user = null;
        $this->loggedOut = true;
    }
    public function logoutCurrentDevice()
    {
        $user = $this->user();
        $this->clearUserDataFromStorage();
        if (isset($this->events)) {
            $this->events->dispatch(new CurrentDeviceLogout($this->name, $user));
        }
        $this->user = null;
        $this->loggedOut = true;
    }
    protected function clearUserDataFromStorage()
    {
        $this->session->remove($this->getName());
        $this->getCookieJar()->unqueue($this->getRecallerName());
        if (!is_null($this->recaller())) {
            $this->getCookieJar()->queue($this->getCookieJar()->forget($this->getRecallerName()));
        }
    }
    protected function cycleRememberToken(AuthenticatableContract $user)
    {
        $user->setRememberToken($token = Str::random(60));
        $this->provider->updateRememberToken($user, $token);
    }
    public function logoutOtherDevices($password, $attribute = 'password')
    {
        if (!$this->user()) {
            return;
        }
        $result = $this->rehashUserPassword($password, $attribute);
        if ($this->recaller() || $this->getCookieJar()->hasQueued($this->getRecallerName())) {
            $this->queueRecallerCookie($this->user());
        }
        $this->fireOtherDeviceLogoutEvent($this->user());
        return $result;
    }
    protected function rehashUserPassword($password, $attribute)
    {
        if (!Hash::check($password, $this->user()->{$attribute})) {
            throw new InvalidArgumentException('The given password does not match the current password.');
        }
        return tap($this->user()->forceFill([$attribute => Hash::make($password)]))->save();
    }
    public function attempting($callback)
    {
        $this->events?->listen(Events\Attempting::class, $callback);
    }
    protected function fireAttemptEvent(array $credentials, $remember = false)
    {
        $this->events?->dispatch(new Attempting($this->name, $credentials, $remember));
    }
    protected function fireValidatedEvent($user)
    {
        $this->events?->dispatch(new Validated($this->name, $user));
    }
    protected function fireLoginEvent($user, $remember = false)
    {
        $this->events?->dispatch(new Login($this->name, $user, $remember));
    }
    protected function fireAuthenticatedEvent($user)
    {
        $this->events?->dispatch(new Authenticated($this->name, $user));
    }
    protected function fireOtherDeviceLogoutEvent($user)
    {
        $this->events?->dispatch(new OtherDeviceLogout($this->name, $user));
    }
    protected function fireFailedEvent($user, array $credentials)
    {
        $this->events?->dispatch(new Failed($this->name, $user, $credentials));
    }
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }
    public function getName()
    {
        return 'login_' . $this->name . '_' . sha1(static::class);
    }
    public function getRecallerName()
    {
        return 'remember_' . $this->name . '_' . sha1(static::class);
    }
    public function viaRemember()
    {
        return $this->viaRemember;
    }
    protected function getRememberDuration()
    {
        return $this->rememberDuration;
    }
    public function setRememberDuration($minutes)
    {
        $this->rememberDuration = $minutes;
        return $this;
    }
    public function getCookieJar()
    {
        if (!isset($this->cookie)) {
            throw new RuntimeException('Cookie jar has not been set.');
        }
        return $this->cookie;
    }
    public function setCookieJar(CookieJar $cookie)
    {
        $this->cookie = $cookie;
    }
    public function getDispatcher()
    {
        return $this->events;
    }
    public function setDispatcher(Dispatcher $events)
    {
        $this->events = $events;
    }
    public function getSession()
    {
        return $this->session;
    }
    public function getUser()
    {
        return $this->user;
    }
    public function setUser(AuthenticatableContract $user)
    {
        $this->user = $user;
        $this->loggedOut = false;
        $this->fireAuthenticatedEvent($user);
        return $this;
    }
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }
    public function setRequest(Request $request)
    {
        $this->request = $request;
        return $this;
    }
    public function getTimebox()
    {
        return $this->timebox;
    }
}
}

namespace Illuminate\Auth\Access {
use Closure;
use Exception;
use Illuminate\Auth\Access\Events\GateEvaluated;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use InvalidArgumentException;
use ReflectionClass;
use ReflectionFunction;
class Gate implements GateContract
{
    use HandlesAuthorization;
    protected $container;
    protected $userResolver;
    protected $abilities = [];
    protected $policies = [];
    protected $beforeCallbacks = [];
    protected $afterCallbacks = [];
    protected $stringCallbacks = [];
    protected $defaultDenialResponse;
    protected $guessPolicyNamesUsingCallback;
    public function __construct(Container $container, callable $userResolver, array $abilities = [], array $policies = [], array $beforeCallbacks = [], array $afterCallbacks = [], ?callable $guessPolicyNamesUsingCallback = null)
    {
        $this->policies = $policies;
        $this->container = $container;
        $this->abilities = $abilities;
        $this->userResolver = $userResolver;
        $this->afterCallbacks = $afterCallbacks;
        $this->beforeCallbacks = $beforeCallbacks;
        $this->guessPolicyNamesUsingCallback = $guessPolicyNamesUsingCallback;
    }
    public function has($ability)
    {
        $abilities = is_array($ability) ? $ability : func_get_args();
        foreach ($abilities as $ability) {
            if (!isset($this->abilities[$ability])) {
                return false;
            }
        }
        return true;
    }
    public function allowIf($condition, $message = null, $code = null)
    {
        return $this->authorizeOnDemand($condition, $message, $code, true);
    }
    public function denyIf($condition, $message = null, $code = null)
    {
        return $this->authorizeOnDemand($condition, $message, $code, false);
    }
    protected function authorizeOnDemand($condition, $message, $code, $allowWhenResponseIs)
    {
        $user = $this->resolveUser();
        if ($condition instanceof Closure) {
            $response = $this->canBeCalledWithUser($user, $condition) ? $condition($user) : new Response(false, $message, $code);
        } else {
            $response = $condition;
        }
        return with($response instanceof Response ? $response : new Response((bool) $response === $allowWhenResponseIs, $message, $code))->authorize();
    }
    public function define($ability, $callback)
    {
        if (is_array($callback) && isset($callback[0]) && is_string($callback[0])) {
            $callback = $callback[0] . '@' . $callback[1];
        }
        if (is_callable($callback)) {
            $this->abilities[$ability] = $callback;
        } elseif (is_string($callback)) {
            $this->stringCallbacks[$ability] = $callback;
            $this->abilities[$ability] = $this->buildAbilityCallback($ability, $callback);
        } else {
            throw new InvalidArgumentException("Callback must be a callable, callback array, or a 'Class@method' string.");
        }
        return $this;
    }
    public function resource($name, $class, ?array $abilities = null)
    {
        $abilities = $abilities ?: ['viewAny' => 'viewAny', 'view' => 'view', 'create' => 'create', 'update' => 'update', 'delete' => 'delete'];
        foreach ($abilities as $ability => $method) {
            $this->define($name . '.' . $ability, $class . '@' . $method);
        }
        return $this;
    }
    protected function buildAbilityCallback($ability, $callback)
    {
        return function () use ($ability, $callback) {
            if (str_contains($callback, '@')) {
                [$class, $method] = Str::parseCallback($callback);
            } else {
                $class = $callback;
            }
            $policy = $this->resolvePolicy($class);
            $arguments = func_get_args();
            $user = array_shift($arguments);
            $result = $this->callPolicyBefore($policy, $user, $ability, $arguments);
            if (!is_null($result)) {
                return $result;
            }
            return isset($method) ? $policy->{$method}(...func_get_args()) : $policy(...func_get_args());
        };
    }
    public function policy($class, $policy)
    {
        $this->policies[$class] = $policy;
        return $this;
    }
    public function before(callable $callback)
    {
        $this->beforeCallbacks[] = $callback;
        return $this;
    }
    public function after(callable $callback)
    {
        $this->afterCallbacks[] = $callback;
        return $this;
    }
    public function allows($ability, $arguments = [])
    {
        return $this->check($ability, $arguments);
    }
    public function denies($ability, $arguments = [])
    {
        return !$this->allows($ability, $arguments);
    }
    public function check($abilities, $arguments = [])
    {
        return collect($abilities)->every(fn($ability) => $this->inspect($ability, $arguments)->allowed());
    }
    public function any($abilities, $arguments = [])
    {
        return collect($abilities)->contains(fn($ability) => $this->check($ability, $arguments));
    }
    public function none($abilities, $arguments = [])
    {
        return !$this->any($abilities, $arguments);
    }
    public function authorize($ability, $arguments = [])
    {
        return $this->inspect($ability, $arguments)->authorize();
    }
    public function inspect($ability, $arguments = [])
    {
        try {
            $result = $this->raw($ability, $arguments);
            if ($result instanceof Response) {
                return $result;
            }
            return $result ? Response::allow() : $this->defaultDenialResponse ?? Response::deny();
        } catch (AuthorizationException $e) {
            return $e->toResponse();
        }
    }
    public function raw($ability, $arguments = [])
    {
        $arguments = Arr::wrap($arguments);
        $user = $this->resolveUser();
        $result = $this->callBeforeCallbacks($user, $ability, $arguments);
        if (is_null($result)) {
            $result = $this->callAuthCallback($user, $ability, $arguments);
        }
        return tap($this->callAfterCallbacks($user, $ability, $arguments, $result), function ($result) use ($user, $ability, $arguments) {
            $this->dispatchGateEvaluatedEvent($user, $ability, $arguments, $result);
        });
    }
    protected function canBeCalledWithUser($user, $class, $method = null)
    {
        if (!is_null($user)) {
            return true;
        }
        if (!is_null($method)) {
            return $this->methodAllowsGuests($class, $method);
        }
        if (is_array($class)) {
            $className = is_string($class[0]) ? $class[0] : get_class($class[0]);
            return $this->methodAllowsGuests($className, $class[1]);
        }
        return $this->callbackAllowsGuests($class);
    }
    protected function methodAllowsGuests($class, $method)
    {
        try {
            $reflection = new ReflectionClass($class);
            $method = $reflection->getMethod($method);
        } catch (Exception) {
            return false;
        }
        if ($method) {
            $parameters = $method->getParameters();
            return isset($parameters[0]) && $this->parameterAllowsGuests($parameters[0]);
        }
        return false;
    }
    protected function callbackAllowsGuests($callback)
    {
        $parameters = (new ReflectionFunction($callback))->getParameters();
        return isset($parameters[0]) && $this->parameterAllowsGuests($parameters[0]);
    }
    protected function parameterAllowsGuests($parameter)
    {
        return $parameter->hasType() && $parameter->allowsNull() || $parameter->isDefaultValueAvailable() && is_null($parameter->getDefaultValue());
    }
    protected function callAuthCallback($user, $ability, array $arguments)
    {
        $callback = $this->resolveAuthCallback($user, $ability, $arguments);
        return $callback($user, ...$arguments);
    }
    protected function callBeforeCallbacks($user, $ability, array $arguments)
    {
        foreach ($this->beforeCallbacks as $before) {
            if (!$this->canBeCalledWithUser($user, $before)) {
                continue;
            }
            if (!is_null($result = $before($user, $ability, $arguments))) {
                return $result;
            }
        }
    }
    protected function callAfterCallbacks($user, $ability, array $arguments, $result)
    {
        foreach ($this->afterCallbacks as $after) {
            if (!$this->canBeCalledWithUser($user, $after)) {
                continue;
            }
            $afterResult = $after($user, $ability, $result, $arguments);
            $result ??= $afterResult;
        }
        return $result;
    }
    protected function dispatchGateEvaluatedEvent($user, $ability, array $arguments, $result)
    {
        if ($this->container->bound(Dispatcher::class)) {
            $this->container->make(Dispatcher::class)->dispatch(new GateEvaluated($user, $ability, $result, $arguments));
        }
    }
    protected function resolveAuthCallback($user, $ability, array $arguments)
    {
        if (isset($arguments[0]) && !is_null($policy = $this->getPolicyFor($arguments[0])) && $callback = $this->resolvePolicyCallback($user, $ability, $arguments, $policy)) {
            return $callback;
        }
        if (isset($this->stringCallbacks[$ability])) {
            [$class, $method] = Str::parseCallback($this->stringCallbacks[$ability]);
            if ($this->canBeCalledWithUser($user, $class, $method ?: '__invoke')) {
                return $this->abilities[$ability];
            }
        }
        if (isset($this->abilities[$ability]) && $this->canBeCalledWithUser($user, $this->abilities[$ability])) {
            return $this->abilities[$ability];
        }
        return function () {
        };
    }
    public function getPolicyFor($class)
    {
        if (is_object($class)) {
            $class = get_class($class);
        }
        if (!is_string($class)) {
            return;
        }
        if (isset($this->policies[$class])) {
            return $this->resolvePolicy($this->policies[$class]);
        }
        foreach ($this->guessPolicyName($class) as $guessedPolicy) {
            if (class_exists($guessedPolicy)) {
                return $this->resolvePolicy($guessedPolicy);
            }
        }
        foreach ($this->policies as $expected => $policy) {
            if (is_subclass_of($class, $expected)) {
                return $this->resolvePolicy($policy);
            }
        }
    }
    protected function guessPolicyName($class)
    {
        if ($this->guessPolicyNamesUsingCallback) {
            return Arr::wrap(call_user_func($this->guessPolicyNamesUsingCallback, $class));
        }
        $classDirname = str_replace('/', '\\', dirname(str_replace('\\', '/', $class)));
        $classDirnameSegments = explode('\\', $classDirname);
        return Arr::wrap(Collection::times(count($classDirnameSegments), function ($index) use ($class, $classDirnameSegments) {
            $classDirname = implode('\\', array_slice($classDirnameSegments, 0, $index));
            return $classDirname . '\Policies\\' . class_basename($class) . 'Policy';
        })->reverse()->values()->first(function ($class) {
            return class_exists($class);
        }) ?: [$classDirname . '\Policies\\' . class_basename($class) . 'Policy']);
    }
    public function guessPolicyNamesUsing(callable $callback)
    {
        $this->guessPolicyNamesUsingCallback = $callback;
        return $this;
    }
    public function resolvePolicy($class)
    {
        return $this->container->make($class);
    }
    protected function resolvePolicyCallback($user, $ability, array $arguments, $policy)
    {
        if (!is_callable([$policy, $this->formatAbilityToMethod($ability)])) {
            return false;
        }
        return function () use ($user, $ability, $arguments, $policy) {
            $result = $this->callPolicyBefore($policy, $user, $ability, $arguments);
            if (!is_null($result)) {
                return $result;
            }
            $method = $this->formatAbilityToMethod($ability);
            return $this->callPolicyMethod($policy, $method, $user, $arguments);
        };
    }
    protected function callPolicyBefore($policy, $user, $ability, $arguments)
    {
        if (!method_exists($policy, 'before')) {
            return;
        }
        if ($this->canBeCalledWithUser($user, $policy, 'before')) {
            return $policy->before($user, $ability, ...$arguments);
        }
    }
    protected function callPolicyMethod($policy, $method, $user, array $arguments)
    {
        if (isset($arguments[0]) && is_string($arguments[0])) {
            array_shift($arguments);
        }
        if (!is_callable([$policy, $method])) {
            return;
        }
        if ($this->canBeCalledWithUser($user, $policy, $method)) {
            return $policy->{$method}($user, ...$arguments);
        }
    }
    protected function formatAbilityToMethod($ability)
    {
        return str_contains($ability, '-') ? Str::camel($ability) : $ability;
    }
    public function forUser($user)
    {
        $callback = fn() => $user;
        return new static($this->container, $callback, $this->abilities, $this->policies, $this->beforeCallbacks, $this->afterCallbacks, $this->guessPolicyNamesUsingCallback);
    }
    protected function resolveUser()
    {
        return call_user_func($this->userResolver);
    }
    public function abilities()
    {
        return $this->abilities;
    }
    public function policies()
    {
        return $this->policies;
    }
    public function defaultDenialResponse(Response $response)
    {
        $this->defaultDenialResponse = $response;
        return $this;
    }
    public function setContainer(Container $container)
    {
        $this->container = $container;
        return $this;
    }
}
}

namespace Illuminate\Auth {
use Closure;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Contracts\Support\Arrayable;
class EloquentUserProvider implements UserProvider
{
    protected $hasher;
    protected $model;
    protected $queryCallback;
    public function __construct(HasherContract $hasher, $model)
    {
        $this->model = $model;
        $this->hasher = $hasher;
    }
    public function retrieveById($identifier)
    {
        $model = $this->createModel();
        return $this->newModelQuery($model)->where($model->getAuthIdentifierName(), $identifier)->first();
    }
    public function retrieveByToken($identifier, $token)
    {
        $model = $this->createModel();
        $retrievedModel = $this->newModelQuery($model)->where($model->getAuthIdentifierName(), $identifier)->first();
        if (!$retrievedModel) {
            return;
        }
        $rememberToken = $retrievedModel->getRememberToken();
        return $rememberToken && hash_equals($rememberToken, $token) ? $retrievedModel : null;
    }
    public function updateRememberToken(UserContract $user, $token)
    {
        $user->setRememberToken($token);
        $timestamps = $user->timestamps;
        $user->timestamps = false;
        $user->save();
        $user->timestamps = $timestamps;
    }
    public function retrieveByCredentials(array $credentials)
    {
        $credentials = array_filter($credentials, fn($key) => !str_contains($key, 'password'), ARRAY_FILTER_USE_KEY);
        if (empty($credentials)) {
            return;
        }
        $query = $this->newModelQuery();
        foreach ($credentials as $key => $value) {
            if (is_array($value) || $value instanceof Arrayable) {
                $query->whereIn($key, $value);
            } elseif ($value instanceof Closure) {
                $value($query);
            } else {
                $query->where($key, $value);
            }
        }
        return $query->first();
    }
    public function validateCredentials(UserContract $user, array $credentials)
    {
        if (is_null($plain = $credentials['password'])) {
            return false;
        }
        return $this->hasher->check($plain, $user->getAuthPassword());
    }
    protected function newModelQuery($model = null)
    {
        $query = is_null($model) ? $this->createModel()->newQuery() : $model->newQuery();
        with($query, $this->queryCallback);
        return $query;
    }
    public function createModel()
    {
        $class = '\\' . ltrim($this->model, '\\');
        return new $class();
    }
    public function getHasher()
    {
        return $this->hasher;
    }
    public function setHasher(HasherContract $hasher)
    {
        $this->hasher = $hasher;
        return $this;
    }
    public function getModel()
    {
        return $this->model;
    }
    public function setModel($model)
    {
        $this->model = $model;
        return $this;
    }
    public function getQueryCallback()
    {
        return $this->queryCallback;
    }
    public function withQuery($queryCallback = null)
    {
        $this->queryCallback = $queryCallback;
        return $this;
    }
}
}

namespace Illuminate\Auth {
use Illuminate\Auth\Access\Gate;
use Illuminate\Auth\Middleware\RequirePassword;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Contracts\Routing\UrlGenerator;
use Illuminate\Support\ServiceProvider;
class AuthServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->registerAuthenticator();
        $this->registerUserResolver();
        $this->registerAccessGate();
        $this->registerRequirePassword();
        $this->registerRequestRebindHandler();
        $this->registerEventRebindHandler();
    }
    protected function registerAuthenticator()
    {
        $this->app->singleton('auth', fn($app) => new AuthManager($app));
        $this->app->singleton('auth.driver', fn($app) => $app['auth']->guard());
    }
    protected function registerUserResolver()
    {
        $this->app->bind(AuthenticatableContract::class, fn($app) => call_user_func($app['auth']->userResolver()));
    }
    protected function registerAccessGate()
    {
        $this->app->singleton(GateContract::class, function ($app) {
            return new Gate($app, fn() => call_user_func($app['auth']->userResolver()));
        });
    }
    protected function registerRequirePassword()
    {
        $this->app->bind(RequirePassword::class, function ($app) {
            return new RequirePassword($app[ResponseFactory::class], $app[UrlGenerator::class], $app['config']->get('auth.password_timeout'));
        });
    }
    protected function registerRequestRebindHandler()
    {
        $this->app->rebinding('request', function ($app, $request) {
            $request->setUserResolver(function ($guard = null) use ($app) {
                return call_user_func($app['auth']->userResolver(), $guard);
            });
        });
    }
    protected function registerEventRebindHandler()
    {
        $this->app->rebinding('events', function ($app, $dispatcher) {
            if (!$app->resolved('auth') || $app['auth']->hasResolvedGuards() === false) {
                return;
            }
            if (method_exists($guard = $app['auth']->guard(), 'setDispatcher')) {
                $guard->setDispatcher($dispatcher);
            }
        });
    }
}
}

namespace Illuminate\Container {
use ArrayAccess;
use Closure;
use Exception;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\CircularDependencyException;
use Illuminate\Contracts\Container\Container as ContainerContract;
use LogicException;
use ReflectionClass;
use ReflectionException;
use ReflectionFunction;
use ReflectionParameter;
use TypeError;
class Container implements ArrayAccess, ContainerContract
{
    protected static $instance;
    protected $resolved = [];
    protected $bindings = [];
    protected $methodBindings = [];
    protected $instances = [];
    protected $scopedInstances = [];
    protected $aliases = [];
    protected $abstractAliases = [];
    protected $extenders = [];
    protected $tags = [];
    protected $buildStack = [];
    protected $with = [];
    public $contextual = [];
    protected $reboundCallbacks = [];
    protected $globalBeforeResolvingCallbacks = [];
    protected $globalResolvingCallbacks = [];
    protected $globalAfterResolvingCallbacks = [];
    protected $beforeResolvingCallbacks = [];
    protected $resolvingCallbacks = [];
    protected $afterResolvingCallbacks = [];
    public function when($concrete)
    {
        $aliases = [];
        foreach (Util::arrayWrap($concrete) as $c) {
            $aliases[] = $this->getAlias($c);
        }
        return new ContextualBindingBuilder($this, $aliases);
    }
    public function bound($abstract)
    {
        return isset($this->bindings[$abstract]) || isset($this->instances[$abstract]) || $this->isAlias($abstract);
    }
    public function has(string $id): bool
    {
        return $this->bound($id);
    }
    public function resolved($abstract)
    {
        if ($this->isAlias($abstract)) {
            $abstract = $this->getAlias($abstract);
        }
        return isset($this->resolved[$abstract]) || isset($this->instances[$abstract]);
    }
    public function isShared($abstract)
    {
        return isset($this->instances[$abstract]) || isset($this->bindings[$abstract]['shared']) && $this->bindings[$abstract]['shared'] === true;
    }
    public function isAlias($name)
    {
        return isset($this->aliases[$name]);
    }
    public function bind($abstract, $concrete = null, $shared = false)
    {
        $this->dropStaleInstances($abstract);
        if (is_null($concrete)) {
            $concrete = $abstract;
        }
        if (!$concrete instanceof Closure) {
            if (!is_string($concrete)) {
                throw new TypeError(self::class . '::bind(): Argument #2 ($concrete) must be of type Closure|string|null');
            }
            $concrete = $this->getClosure($abstract, $concrete);
        }
        $this->bindings[$abstract] = compact('concrete', 'shared');
        if ($this->resolved($abstract)) {
            $this->rebound($abstract);
        }
    }
    protected function getClosure($abstract, $concrete)
    {
        return function ($container, $parameters = []) use ($abstract, $concrete) {
            if ($abstract == $concrete) {
                return $container->build($concrete);
            }
            return $container->resolve($concrete, $parameters, $raiseEvents = false);
        };
    }
    public function hasMethodBinding($method)
    {
        return isset($this->methodBindings[$method]);
    }
    public function bindMethod($method, $callback)
    {
        $this->methodBindings[$this->parseBindMethod($method)] = $callback;
    }
    protected function parseBindMethod($method)
    {
        if (is_array($method)) {
            return $method[0] . '@' . $method[1];
        }
        return $method;
    }
    public function callMethodBinding($method, $instance)
    {
        return call_user_func($this->methodBindings[$method], $instance, $this);
    }
    public function addContextualBinding($concrete, $abstract, $implementation)
    {
        $this->contextual[$concrete][$this->getAlias($abstract)] = $implementation;
    }
    public function bindIf($abstract, $concrete = null, $shared = false)
    {
        if (!$this->bound($abstract)) {
            $this->bind($abstract, $concrete, $shared);
        }
    }
    public function singleton($abstract, $concrete = null)
    {
        $this->bind($abstract, $concrete, true);
    }
    public function singletonIf($abstract, $concrete = null)
    {
        if (!$this->bound($abstract)) {
            $this->singleton($abstract, $concrete);
        }
    }
    public function scoped($abstract, $concrete = null)
    {
        $this->scopedInstances[] = $abstract;
        $this->singleton($abstract, $concrete);
    }
    public function scopedIf($abstract, $concrete = null)
    {
        if (!$this->bound($abstract)) {
            $this->scoped($abstract, $concrete);
        }
    }
    public function extend($abstract, Closure $closure)
    {
        $abstract = $this->getAlias($abstract);
        if (isset($this->instances[$abstract])) {
            $this->instances[$abstract] = $closure($this->instances[$abstract], $this);
            $this->rebound($abstract);
        } else {
            $this->extenders[$abstract][] = $closure;
            if ($this->resolved($abstract)) {
                $this->rebound($abstract);
            }
        }
    }
    public function instance($abstract, $instance)
    {
        $this->removeAbstractAlias($abstract);
        $isBound = $this->bound($abstract);
        unset($this->aliases[$abstract]);
        $this->instances[$abstract] = $instance;
        if ($isBound) {
            $this->rebound($abstract);
        }
        return $instance;
    }
    protected function removeAbstractAlias($searched)
    {
        if (!isset($this->aliases[$searched])) {
            return;
        }
        foreach ($this->abstractAliases as $abstract => $aliases) {
            foreach ($aliases as $index => $alias) {
                if ($alias == $searched) {
                    unset($this->abstractAliases[$abstract][$index]);
                }
            }
        }
    }
    public function tag($abstracts, $tags)
    {
        $tags = is_array($tags) ? $tags : array_slice(func_get_args(), 1);
        foreach ($tags as $tag) {
            if (!isset($this->tags[$tag])) {
                $this->tags[$tag] = [];
            }
            foreach ((array) $abstracts as $abstract) {
                $this->tags[$tag][] = $abstract;
            }
        }
    }
    public function tagged($tag)
    {
        if (!isset($this->tags[$tag])) {
            return [];
        }
        return new RewindableGenerator(function () use ($tag) {
            foreach ($this->tags[$tag] as $abstract) {
                yield $this->make($abstract);
            }
        }, count($this->tags[$tag]));
    }
    public function alias($abstract, $alias)
    {
        if ($alias === $abstract) {
            throw new LogicException("[{$abstract}] is aliased to itself.");
        }
        $this->aliases[$alias] = $abstract;
        $this->abstractAliases[$abstract][] = $alias;
    }
    public function rebinding($abstract, Closure $callback)
    {
        $this->reboundCallbacks[$abstract = $this->getAlias($abstract)][] = $callback;
        if ($this->bound($abstract)) {
            return $this->make($abstract);
        }
    }
    public function refresh($abstract, $target, $method)
    {
        return $this->rebinding($abstract, function ($app, $instance) use ($target, $method) {
            $target->{$method}($instance);
        });
    }
    protected function rebound($abstract)
    {
        $instance = $this->make($abstract);
        foreach ($this->getReboundCallbacks($abstract) as $callback) {
            $callback($this, $instance);
        }
    }
    protected function getReboundCallbacks($abstract)
    {
        return $this->reboundCallbacks[$abstract] ?? [];
    }
    public function wrap(Closure $callback, array $parameters = [])
    {
        return fn() => $this->call($callback, $parameters);
    }
    public function call($callback, array $parameters = [], $defaultMethod = null)
    {
        $pushedToBuildStack = false;
        if (($className = $this->getClassForCallable($callback)) && !in_array($className, $this->buildStack, true)) {
            $this->buildStack[] = $className;
            $pushedToBuildStack = true;
        }
        $result = BoundMethod::call($this, $callback, $parameters, $defaultMethod);
        if ($pushedToBuildStack) {
            array_pop($this->buildStack);
        }
        return $result;
    }
    protected function getClassForCallable($callback)
    {
        if (PHP_VERSION_ID >= 80200) {
            if (is_callable($callback) && !($reflector = new ReflectionFunction($callback(...)))->isAnonymous()) {
                return $reflector->getClosureScopeClass()->name ?? false;
            }
            return false;
        }
        if (!is_array($callback)) {
            return false;
        }
        return is_string($callback[0]) ? $callback[0] : get_class($callback[0]);
    }
    public function factory($abstract)
    {
        return fn() => $this->make($abstract);
    }
    public function makeWith($abstract, array $parameters = [])
    {
        return $this->make($abstract, $parameters);
    }
    public function make($abstract, array $parameters = [])
    {
        return $this->resolve($abstract, $parameters);
    }
    public function get(string $id)
    {
        try {
            return $this->resolve($id);
        } catch (Exception $e) {
            if ($this->has($id) || $e instanceof CircularDependencyException) {
                throw $e;
            }
            throw new EntryNotFoundException($id, is_int($e->getCode()) ? $e->getCode() : 0, $e);
        }
    }
    protected function resolve($abstract, $parameters = [], $raiseEvents = true)
    {
        $abstract = $this->getAlias($abstract);
        if ($raiseEvents) {
            $this->fireBeforeResolvingCallbacks($abstract, $parameters);
        }
        $concrete = $this->getContextualConcrete($abstract);
        $needsContextualBuild = !empty($parameters) || !is_null($concrete);
        if (isset($this->instances[$abstract]) && !$needsContextualBuild) {
            return $this->instances[$abstract];
        }
        $this->with[] = $parameters;
        if (is_null($concrete)) {
            $concrete = $this->getConcrete($abstract);
        }
        $object = $this->isBuildable($concrete, $abstract) ? $this->build($concrete) : $this->make($concrete);
        foreach ($this->getExtenders($abstract) as $extender) {
            $object = $extender($object, $this);
        }
        if ($this->isShared($abstract) && !$needsContextualBuild) {
            $this->instances[$abstract] = $object;
        }
        if ($raiseEvents) {
            $this->fireResolvingCallbacks($abstract, $object);
        }
        $this->resolved[$abstract] = true;
        array_pop($this->with);
        return $object;
    }
    protected function getConcrete($abstract)
    {
        if (isset($this->bindings[$abstract])) {
            return $this->bindings[$abstract]['concrete'];
        }
        return $abstract;
    }
    protected function getContextualConcrete($abstract)
    {
        if (!is_null($binding = $this->findInContextualBindings($abstract))) {
            return $binding;
        }
        if (empty($this->abstractAliases[$abstract])) {
            return;
        }
        foreach ($this->abstractAliases[$abstract] as $alias) {
            if (!is_null($binding = $this->findInContextualBindings($alias))) {
                return $binding;
            }
        }
    }
    protected function findInContextualBindings($abstract)
    {
        return $this->contextual[end($this->buildStack)][$abstract] ?? null;
    }
    protected function isBuildable($concrete, $abstract)
    {
        return $concrete === $abstract || $concrete instanceof Closure;
    }
    public function build($concrete)
    {
        if ($concrete instanceof Closure) {
            return $concrete($this, $this->getLastParameterOverride());
        }
        try {
            $reflector = new ReflectionClass($concrete);
        } catch (ReflectionException $e) {
            throw new BindingResolutionException("Target class [{$concrete}] does not exist.", 0, $e);
        }
        if (!$reflector->isInstantiable()) {
            return $this->notInstantiable($concrete);
        }
        $this->buildStack[] = $concrete;
        $constructor = $reflector->getConstructor();
        if (is_null($constructor)) {
            array_pop($this->buildStack);
            return new $concrete();
        }
        $dependencies = $constructor->getParameters();
        try {
            $instances = $this->resolveDependencies($dependencies);
        } catch (BindingResolutionException $e) {
            array_pop($this->buildStack);
            throw $e;
        }
        array_pop($this->buildStack);
        return $reflector->newInstanceArgs($instances);
    }
    protected function resolveDependencies(array $dependencies)
    {
        $results = [];
        foreach ($dependencies as $dependency) {
            if ($this->hasParameterOverride($dependency)) {
                $results[] = $this->getParameterOverride($dependency);
                continue;
            }
            $result = is_null(Util::getParameterClassName($dependency)) ? $this->resolvePrimitive($dependency) : $this->resolveClass($dependency);
            if ($dependency->isVariadic()) {
                $results = array_merge($results, $result);
            } else {
                $results[] = $result;
            }
        }
        return $results;
    }
    protected function hasParameterOverride($dependency)
    {
        return array_key_exists($dependency->name, $this->getLastParameterOverride());
    }
    protected function getParameterOverride($dependency)
    {
        return $this->getLastParameterOverride()[$dependency->name];
    }
    protected function getLastParameterOverride()
    {
        return count($this->with) ? end($this->with) : [];
    }
    protected function resolvePrimitive(ReflectionParameter $parameter)
    {
        if (!is_null($concrete = $this->getContextualConcrete('$' . $parameter->getName()))) {
            return Util::unwrapIfClosure($concrete, $this);
        }
        if ($parameter->isDefaultValueAvailable()) {
            return $parameter->getDefaultValue();
        }
        if ($parameter->isVariadic()) {
            return [];
        }
        $this->unresolvablePrimitive($parameter);
    }
    protected function resolveClass(ReflectionParameter $parameter)
    {
        try {
            return $parameter->isVariadic() ? $this->resolveVariadicClass($parameter) : $this->make(Util::getParameterClassName($parameter));
        } catch (BindingResolutionException $e) {
            if ($parameter->isDefaultValueAvailable()) {
                array_pop($this->with);
                return $parameter->getDefaultValue();
            }
            if ($parameter->isVariadic()) {
                array_pop($this->with);
                return [];
            }
            throw $e;
        }
    }
    protected function resolveVariadicClass(ReflectionParameter $parameter)
    {
        $className = Util::getParameterClassName($parameter);
        $abstract = $this->getAlias($className);
        if (!is_array($concrete = $this->getContextualConcrete($abstract))) {
            return $this->make($className);
        }
        return array_map(fn($abstract) => $this->resolve($abstract), $concrete);
    }
    protected function notInstantiable($concrete)
    {
        if (!empty($this->buildStack)) {
            $previous = implode(', ', $this->buildStack);
            $message = "Target [{$concrete}] is not instantiable while building [{$previous}].";
        } else {
            $message = "Target [{$concrete}] is not instantiable.";
        }
        throw new BindingResolutionException($message);
    }
    protected function unresolvablePrimitive(ReflectionParameter $parameter)
    {
        $message = "Unresolvable dependency resolving [{$parameter}] in class {$parameter->getDeclaringClass()->getName()}";
        throw new BindingResolutionException($message);
    }
    public function beforeResolving($abstract, ?Closure $callback = null)
    {
        if (is_string($abstract)) {
            $abstract = $this->getAlias($abstract);
        }
        if ($abstract instanceof Closure && is_null($callback)) {
            $this->globalBeforeResolvingCallbacks[] = $abstract;
        } else {
            $this->beforeResolvingCallbacks[$abstract][] = $callback;
        }
    }
    public function resolving($abstract, ?Closure $callback = null)
    {
        if (is_string($abstract)) {
            $abstract = $this->getAlias($abstract);
        }
        if (is_null($callback) && $abstract instanceof Closure) {
            $this->globalResolvingCallbacks[] = $abstract;
        } else {
            $this->resolvingCallbacks[$abstract][] = $callback;
        }
    }
    public function afterResolving($abstract, ?Closure $callback = null)
    {
        if (is_string($abstract)) {
            $abstract = $this->getAlias($abstract);
        }
        if ($abstract instanceof Closure && is_null($callback)) {
            $this->globalAfterResolvingCallbacks[] = $abstract;
        } else {
            $this->afterResolvingCallbacks[$abstract][] = $callback;
        }
    }
    protected function fireBeforeResolvingCallbacks($abstract, $parameters = [])
    {
        $this->fireBeforeCallbackArray($abstract, $parameters, $this->globalBeforeResolvingCallbacks);
        foreach ($this->beforeResolvingCallbacks as $type => $callbacks) {
            if ($type === $abstract || is_subclass_of($abstract, $type)) {
                $this->fireBeforeCallbackArray($abstract, $parameters, $callbacks);
            }
        }
    }
    protected function fireBeforeCallbackArray($abstract, $parameters, array $callbacks)
    {
        foreach ($callbacks as $callback) {
            $callback($abstract, $parameters, $this);
        }
    }
    protected function fireResolvingCallbacks($abstract, $object)
    {
        $this->fireCallbackArray($object, $this->globalResolvingCallbacks);
        $this->fireCallbackArray($object, $this->getCallbacksForType($abstract, $object, $this->resolvingCallbacks));
        $this->fireAfterResolvingCallbacks($abstract, $object);
    }
    protected function fireAfterResolvingCallbacks($abstract, $object)
    {
        $this->fireCallbackArray($object, $this->globalAfterResolvingCallbacks);
        $this->fireCallbackArray($object, $this->getCallbacksForType($abstract, $object, $this->afterResolvingCallbacks));
    }
    protected function getCallbacksForType($abstract, $object, array $callbacksPerType)
    {
        $results = [];
        foreach ($callbacksPerType as $type => $callbacks) {
            if ($type === $abstract || $object instanceof $type) {
                $results = array_merge($results, $callbacks);
            }
        }
        return $results;
    }
    protected function fireCallbackArray($object, array $callbacks)
    {
        foreach ($callbacks as $callback) {
            $callback($object, $this);
        }
    }
    public function getBindings()
    {
        return $this->bindings;
    }
    public function getAlias($abstract)
    {
        return isset($this->aliases[$abstract]) ? $this->getAlias($this->aliases[$abstract]) : $abstract;
    }
    protected function getExtenders($abstract)
    {
        return $this->extenders[$this->getAlias($abstract)] ?? [];
    }
    public function forgetExtenders($abstract)
    {
        unset($this->extenders[$this->getAlias($abstract)]);
    }
    protected function dropStaleInstances($abstract)
    {
        unset($this->instances[$abstract], $this->aliases[$abstract]);
    }
    public function forgetInstance($abstract)
    {
        unset($this->instances[$abstract]);
    }
    public function forgetInstances()
    {
        $this->instances = [];
    }
    public function forgetScopedInstances()
    {
        foreach ($this->scopedInstances as $scoped) {
            unset($this->instances[$scoped]);
        }
    }
    public function flush()
    {
        $this->aliases = [];
        $this->resolved = [];
        $this->bindings = [];
        $this->instances = [];
        $this->abstractAliases = [];
        $this->scopedInstances = [];
    }
    public static function getInstance()
    {
        if (is_null(static::$instance)) {
            static::$instance = new static();
        }
        return static::$instance;
    }
    public static function setInstance(?ContainerContract $container = null)
    {
        return static::$instance = $container;
    }
    public function offsetExists($key): bool
    {
        return $this->bound($key);
    }
    public function offsetGet($key): mixed
    {
        return $this->make($key);
    }
    public function offsetSet($key, $value): void
    {
        $this->bind($key, $value instanceof Closure ? $value : fn() => $value);
    }
    public function offsetUnset($key): void
    {
        unset($this->bindings[$key], $this->instances[$key], $this->resolved[$key]);
    }
    public function __get($key)
    {
        return $this[$key];
    }
    public function __set($key, $value)
    {
        $this[$key] = $value;
    }
}
}

namespace Symfony\Component\HttpKernel {
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
interface HttpKernelInterface
{
    public const MAIN_REQUEST = 1;
    public const SUB_REQUEST = 2;
    public const MASTER_REQUEST = self::MAIN_REQUEST;
    public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): Response;
}
}

namespace Symfony\Component\HttpKernel {
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
interface TerminableInterface
{
    public function terminate(Request $request, Response $response);
}
}

namespace Illuminate\Http {
use Illuminate\Http\Exceptions\HttpResponseException;
use Symfony\Component\HttpFoundation\HeaderBag;
use Throwable;
trait ResponseTrait
{
    public $original;
    public $exception;
    public function status()
    {
        return $this->getStatusCode();
    }
    public function statusText()
    {
        return $this->statusText;
    }
    public function content()
    {
        return $this->getContent();
    }
    public function getOriginalContent()
    {
        $original = $this->original;
        return $original instanceof self ? $original->{__FUNCTION__}() : $original;
    }
    public function header($key, $values, $replace = true)
    {
        $this->headers->set($key, $values, $replace);
        return $this;
    }
    public function withHeaders($headers)
    {
        if ($headers instanceof HeaderBag) {
            $headers = $headers->all();
        }
        foreach ($headers as $key => $value) {
            $this->headers->set($key, $value);
        }
        return $this;
    }
    public function cookie($cookie)
    {
        return $this->withCookie(...func_get_args());
    }
    public function withCookie($cookie)
    {
        if (is_string($cookie) && function_exists('cookie')) {
            $cookie = cookie(...func_get_args());
        }
        $this->headers->setCookie($cookie);
        return $this;
    }
    public function withoutCookie($cookie, $path = null, $domain = null)
    {
        if (is_string($cookie) && function_exists('cookie')) {
            $cookie = cookie($cookie, null, -2628000, $path, $domain);
        }
        $this->headers->setCookie($cookie);
        return $this;
    }
    public function getCallback()
    {
        return $this->callback ?? null;
    }
    public function withException(Throwable $e)
    {
        $this->exception = $e;
        return $this;
    }
    public function throwResponse()
    {
        throw new HttpResponseException($this);
    }
}
}

namespace Illuminate\Http {
use ArrayObject;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Renderable;
use Illuminate\Support\Traits\Macroable;
use InvalidArgumentException;
use JsonSerializable;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
class Response extends SymfonyResponse
{
    use ResponseTrait, Macroable {
        Macroable::__call as macroCall;
    }
    public function __construct($content = '', $status = 200, array $headers = [])
    {
        $this->headers = new ResponseHeaderBag($headers);
        $this->setContent($content);
        $this->setStatusCode($status);
        $this->setProtocolVersion('1.0');
    }
    public function setContent(mixed $content): static
    {
        $this->original = $content;
        if ($this->shouldBeJson($content)) {
            $this->header('Content-Type', 'application/json');
            $content = $this->morphToJson($content);
            if ($content === false) {
                throw new InvalidArgumentException(json_last_error_msg());
            }
        } elseif ($content instanceof Renderable) {
            $content = $content->render();
        }
        parent::setContent($content);
        return $this;
    }
    protected function shouldBeJson($content)
    {
        return $content instanceof Arrayable || $content instanceof Jsonable || $content instanceof ArrayObject || $content instanceof JsonSerializable || is_array($content);
    }
    protected function morphToJson($content)
    {
        if ($content instanceof Jsonable) {
            return $content->toJson();
        } elseif ($content instanceof Arrayable) {
            return json_encode($content->toArray());
        }
        return json_encode($content);
    }
}
}

namespace Illuminate\Http\Middleware {
use Closure;
class FrameGuard
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN', false);
        return $response;
    }
}
}

namespace Symfony\Component\HttpFoundation {
use Symfony\Component\HttpFoundation\Exception\BadRequestException;
use Symfony\Component\HttpFoundation\Exception\UnexpectedValueException;
class ParameterBag implements \IteratorAggregate, \Countable
{
    protected $parameters;
    public function __construct(array $parameters = [])
    {
        $this->parameters = $parameters;
    }
    public function all(?string $key = null): array
    {
        if (null === $key) {
            return $this->parameters;
        }
        if (!\is_array($value = $this->parameters[$key] ?? [])) {
            throw new BadRequestException(sprintf('Unexpected value for parameter "%s": expecting "array", got "%s".', $key, get_debug_type($value)));
        }
        return $value;
    }
    public function keys(): array
    {
        return array_keys($this->parameters);
    }
    public function replace(array $parameters = [])
    {
        $this->parameters = $parameters;
    }
    public function add(array $parameters = [])
    {
        $this->parameters = array_replace($this->parameters, $parameters);
    }
    public function get(string $key, mixed $default = null): mixed
    {
        return \array_key_exists($key, $this->parameters) ? $this->parameters[$key] : $default;
    }
    public function set(string $key, mixed $value)
    {
        $this->parameters[$key] = $value;
    }
    public function has(string $key): bool
    {
        return \array_key_exists($key, $this->parameters);
    }
    public function remove(string $key)
    {
        unset($this->parameters[$key]);
    }
    public function getAlpha(string $key, string $default = ''): string
    {
        return preg_replace('/[^[:alpha:]]/', '', $this->getString($key, $default));
    }
    public function getAlnum(string $key, string $default = ''): string
    {
        return preg_replace('/[^[:alnum:]]/', '', $this->getString($key, $default));
    }
    public function getDigits(string $key, string $default = ''): string
    {
        return preg_replace('/[^[:digit:]]/', '', $this->getString($key, $default));
    }
    public function getString(string $key, string $default = ''): string
    {
        $value = $this->get($key, $default);
        if (!\is_scalar($value) && !$value instanceof \Stringable) {
            throw new UnexpectedValueException(sprintf('Parameter value "%s" cannot be converted to "string".', $key));
        }
        return (string) $value;
    }
    public function getInt(string $key, int $default = 0): int
    {
        return $this->filter($key, $default, \FILTER_VALIDATE_INT, ['flags' => \FILTER_REQUIRE_SCALAR]) ?: 0;
    }
    public function getBoolean(string $key, bool $default = false): bool
    {
        return $this->filter($key, $default, \FILTER_VALIDATE_BOOL, ['flags' => \FILTER_REQUIRE_SCALAR]);
    }
    public function getEnum(string $key, string $class, ?\BackedEnum $default = null): ?\BackedEnum
    {
        $value = $this->get($key);
        if (null === $value) {
            return $default;
        }
        try {
            return $class::from($value);
        } catch (\ValueError|\TypeError $e) {
            throw new UnexpectedValueException(sprintf('Parameter "%s" cannot be converted to enum: %s.', $key, $e->getMessage()), $e->getCode(), $e);
        }
    }
    public function filter(string $key, mixed $default = null, int $filter = \FILTER_DEFAULT, mixed $options = []): mixed
    {
        $value = $this->get($key, $default);
        if (!\is_array($options) && $options) {
            $options = ['flags' => $options];
        }
        if (\is_array($value) && !isset($options['flags'])) {
            $options['flags'] = \FILTER_REQUIRE_ARRAY;
        }
        if (\is_object($value) && !$value instanceof \Stringable) {
            throw new UnexpectedValueException(sprintf('Parameter value "%s" cannot be filtered.', $key));
        }
        if (\FILTER_CALLBACK & $filter && !($options['options'] ?? null) instanceof \Closure) {
            throw new \InvalidArgumentException(sprintf('A Closure must be passed to "%s()" when FILTER_CALLBACK is used, "%s" given.', __METHOD__, get_debug_type($options['options'] ?? null)));
        }
        $options['flags'] ??= 0;
        $nullOnFailure = $options['flags'] & \FILTER_NULL_ON_FAILURE;
        $options['flags'] |= \FILTER_NULL_ON_FAILURE;
        $value = filter_var($value, $filter, $options);
        if (null !== $value || $nullOnFailure) {
            return $value;
        }
        $method = debug_backtrace(\DEBUG_BACKTRACE_IGNORE_ARGS | \DEBUG_BACKTRACE_PROVIDE_OBJECT, 2)[1];
        $method = ($method['object'] ?? null) === $this ? $method['function'] : 'filter';
        $hint = 'filter' === $method ? 'pass' : 'use method "filter()" with';
        trigger_deprecation('symfony/http-foundation', '6.3', 'Ignoring invalid values when using "%s::%s(\'%s\')" is deprecated and will throw an "%s" in 7.0; ' . $hint . ' flag "FILTER_NULL_ON_FAILURE" to keep ignoring them.', $this::class, $method, $key, UnexpectedValueException::class);
        return false;
    }
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->parameters);
    }
    public function count(): int
    {
        return \count($this->parameters);
    }
}
}

namespace Symfony\Component\HttpFoundation {
use Symfony\Component\HttpFoundation\File\UploadedFile;
class FileBag extends ParameterBag
{
    private const FILE_KEYS = ['error', 'name', 'size', 'tmp_name', 'type'];
    public function __construct(array $parameters = [])
    {
        $this->replace($parameters);
    }
    public function replace(array $files = [])
    {
        $this->parameters = [];
        $this->add($files);
    }
    public function set(string $key, mixed $value)
    {
        if (!\is_array($value) && !$value instanceof UploadedFile) {
            throw new \InvalidArgumentException('An uploaded file must be an array or an instance of UploadedFile.');
        }
        parent::set($key, $this->convertFileInformation($value));
    }
    public function add(array $files = [])
    {
        foreach ($files as $key => $file) {
            $this->set($key, $file);
        }
    }
    protected function convertFileInformation(array|UploadedFile $file): array|UploadedFile|null
    {
        if ($file instanceof UploadedFile) {
            return $file;
        }
        $file = $this->fixPhpFilesArray($file);
        $keys = array_keys($file);
        sort($keys);
        if (self::FILE_KEYS == $keys) {
            if (\UPLOAD_ERR_NO_FILE == $file['error']) {
                $file = null;
            } else {
                $file = new UploadedFile($file['tmp_name'], $file['name'], $file['type'], $file['error'], false);
            }
        } else {
            $file = array_map(fn($v) => $v instanceof UploadedFile || \is_array($v) ? $this->convertFileInformation($v) : $v, $file);
            if (array_keys($keys) === $keys) {
                $file = array_filter($file);
            }
        }
        return $file;
    }
    protected function fixPhpFilesArray(array $data): array
    {
        unset($data['full_path']);
        $keys = array_keys($data);
        sort($keys);
        if (self::FILE_KEYS != $keys || !isset($data['name']) || !\is_array($data['name'])) {
            return $data;
        }
        $files = $data;
        foreach (self::FILE_KEYS as $k) {
            unset($files[$k]);
        }
        foreach ($data['name'] as $key => $name) {
            $files[$key] = $this->fixPhpFilesArray(['error' => $data['error'][$key], 'name' => $name, 'type' => $data['type'][$key], 'tmp_name' => $data['tmp_name'][$key], 'size' => $data['size'][$key]]);
        }
        return $files;
    }
}
}

namespace Symfony\Component\HttpFoundation {
class ServerBag extends ParameterBag
{
    public function getHeaders(): array
    {
        $headers = [];
        foreach ($this->parameters as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $headers[substr($key, 5)] = $value;
            } elseif (\in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH', 'CONTENT_MD5'], true) && '' !== $value) {
                $headers[$key] = $value;
            }
        }
        if (isset($this->parameters['PHP_AUTH_USER'])) {
            $headers['PHP_AUTH_USER'] = $this->parameters['PHP_AUTH_USER'];
            $headers['PHP_AUTH_PW'] = $this->parameters['PHP_AUTH_PW'] ?? '';
        } else {
            $authorizationHeader = null;
            if (isset($this->parameters['HTTP_AUTHORIZATION'])) {
                $authorizationHeader = $this->parameters['HTTP_AUTHORIZATION'];
            } elseif (isset($this->parameters['REDIRECT_HTTP_AUTHORIZATION'])) {
                $authorizationHeader = $this->parameters['REDIRECT_HTTP_AUTHORIZATION'];
            }
            if (null !== $authorizationHeader) {
                if (0 === stripos($authorizationHeader, 'basic ')) {
                    $exploded = explode(':', base64_decode(substr($authorizationHeader, 6)), 2);
                    if (2 == \count($exploded)) {
                        [$headers['PHP_AUTH_USER'], $headers['PHP_AUTH_PW']] = $exploded;
                    }
                } elseif (empty($this->parameters['PHP_AUTH_DIGEST']) && 0 === stripos($authorizationHeader, 'digest ')) {
                    $headers['PHP_AUTH_DIGEST'] = $authorizationHeader;
                    $this->parameters['PHP_AUTH_DIGEST'] = $authorizationHeader;
                } elseif (0 === stripos($authorizationHeader, 'bearer ')) {
                    $headers['AUTHORIZATION'] = $authorizationHeader;
                }
            }
        }
        if (isset($headers['AUTHORIZATION'])) {
            return $headers;
        }
        if (isset($headers['PHP_AUTH_USER'])) {
            $headers['AUTHORIZATION'] = 'Basic ' . base64_encode($headers['PHP_AUTH_USER'] . ':' . ($headers['PHP_AUTH_PW'] ?? ''));
        } elseif (isset($headers['PHP_AUTH_DIGEST'])) {
            $headers['AUTHORIZATION'] = $headers['PHP_AUTH_DIGEST'];
        }
        return $headers;
    }
}
}

namespace Symfony\Component\HttpFoundation {
class HeaderBag implements \IteratorAggregate, \Countable, \Stringable
{
    protected const UPPER = '_ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    protected const LOWER = '-abcdefghijklmnopqrstuvwxyz';
    protected $headers = [];
    protected $cacheControl = [];
    public function __construct(array $headers = [])
    {
        foreach ($headers as $key => $values) {
            $this->set($key, $values);
        }
    }
    public function __toString(): string
    {
        if (!$headers = $this->all()) {
            return '';
        }
        ksort($headers);
        $max = max(array_map('strlen', array_keys($headers))) + 1;
        $content = '';
        foreach ($headers as $name => $values) {
            $name = ucwords($name, '-');
            foreach ($values as $value) {
                $content .= sprintf("%-{$max}s %s\r\n", $name . ':', $value);
            }
        }
        return $content;
    }
    public function all(?string $key = null): array
    {
        if (null !== $key) {
            return $this->headers[strtr($key, self::UPPER, self::LOWER)] ?? [];
        }
        return $this->headers;
    }
    public function keys(): array
    {
        return array_keys($this->all());
    }
    public function replace(array $headers = [])
    {
        $this->headers = [];
        $this->add($headers);
    }
    public function add(array $headers)
    {
        foreach ($headers as $key => $values) {
            $this->set($key, $values);
        }
    }
    public function get(string $key, ?string $default = null): ?string
    {
        $headers = $this->all($key);
        if (!$headers) {
            return $default;
        }
        if (null === $headers[0]) {
            return null;
        }
        return (string) $headers[0];
    }
    public function set(string $key, string|array|null $values, bool $replace = true)
    {
        $key = strtr($key, self::UPPER, self::LOWER);
        if (\is_array($values)) {
            $values = array_values($values);
            if (true === $replace || !isset($this->headers[$key])) {
                $this->headers[$key] = $values;
            } else {
                $this->headers[$key] = array_merge($this->headers[$key], $values);
            }
        } else if (true === $replace || !isset($this->headers[$key])) {
            $this->headers[$key] = [$values];
        } else {
            $this->headers[$key][] = $values;
        }
        if ('cache-control' === $key) {
            $this->cacheControl = $this->parseCacheControl(implode(', ', $this->headers[$key]));
        }
    }
    public function has(string $key): bool
    {
        return \array_key_exists(strtr($key, self::UPPER, self::LOWER), $this->all());
    }
    public function contains(string $key, string $value): bool
    {
        return \in_array($value, $this->all($key));
    }
    public function remove(string $key)
    {
        $key = strtr($key, self::UPPER, self::LOWER);
        unset($this->headers[$key]);
        if ('cache-control' === $key) {
            $this->cacheControl = [];
        }
    }
    public function getDate(string $key, ?\DateTimeInterface $default = null): ?\DateTimeInterface
    {
        if (null === $value = $this->get($key)) {
            return null !== $default ? \DateTimeImmutable::createFromInterface($default) : null;
        }
        if (false === $date = \DateTimeImmutable::createFromFormat(\DATE_RFC2822, $value)) {
            throw new \RuntimeException(sprintf('The "%s" HTTP header is not parseable (%s).', $key, $value));
        }
        return $date;
    }
    public function addCacheControlDirective(string $key, bool|string $value = true)
    {
        $this->cacheControl[$key] = $value;
        $this->set('Cache-Control', $this->getCacheControlHeader());
    }
    public function hasCacheControlDirective(string $key): bool
    {
        return \array_key_exists($key, $this->cacheControl);
    }
    public function getCacheControlDirective(string $key): bool|string|null
    {
        return $this->cacheControl[$key] ?? null;
    }
    public function removeCacheControlDirective(string $key)
    {
        unset($this->cacheControl[$key]);
        $this->set('Cache-Control', $this->getCacheControlHeader());
    }
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->headers);
    }
    public function count(): int
    {
        return \count($this->headers);
    }
    protected function getCacheControlHeader()
    {
        ksort($this->cacheControl);
        return HeaderUtils::toString($this->cacheControl, ',');
    }
    protected function parseCacheControl(string $header): array
    {
        $parts = HeaderUtils::split($header, ',=');
        return HeaderUtils::combine($parts);
    }
}
}

namespace Symfony\Component\HttpFoundation\Session {
use Symfony\Component\HttpFoundation\Session\Storage\MetadataBag;
interface SessionInterface
{
    public function start(): bool;
    public function getId(): string;
    public function setId(string $id);
    public function getName(): string;
    public function setName(string $name);
    public function invalidate(?int $lifetime = null): bool;
    public function migrate(bool $destroy = false, ?int $lifetime = null): bool;
    public function save();
    public function has(string $name): bool;
    public function get(string $name, mixed $default = null): mixed;
    public function set(string $name, mixed $value);
    public function all(): array;
    public function replace(array $attributes);
    public function remove(string $name): mixed;
    public function clear();
    public function isStarted(): bool;
    public function registerBag(SessionBagInterface $bag);
    public function getBag(string $name): SessionBagInterface;
    public function getMetadataBag(): MetadataBag;
}
}

namespace Symfony\Component\HttpFoundation\Session {
interface SessionBagInterface
{
    public function getName(): string;
    public function initialize(array &$array);
    public function getStorageKey(): string;
    public function clear(): mixed;
}
}

namespace Symfony\Component\HttpFoundation\Session\Attribute {
use Symfony\Component\HttpFoundation\Session\SessionBagInterface;
interface AttributeBagInterface extends SessionBagInterface
{
    public function has(string $name): bool;
    public function get(string $name, mixed $default = null): mixed;
    public function set(string $name, mixed $value);
    public function all(): array;
    public function replace(array $attributes);
    public function remove(string $name): mixed;
}
}

namespace Symfony\Component\HttpFoundation\Session\Attribute {
class AttributeBag implements AttributeBagInterface, \IteratorAggregate, \Countable
{
    private string $name = 'attributes';
    private string $storageKey;
    protected $attributes = [];
    public function __construct(string $storageKey = '_sf2_attributes')
    {
        $this->storageKey = $storageKey;
    }
    public function getName(): string
    {
        return $this->name;
    }
    public function setName(string $name)
    {
        $this->name = $name;
    }
    public function initialize(array &$attributes)
    {
        $this->attributes =& $attributes;
    }
    public function getStorageKey(): string
    {
        return $this->storageKey;
    }
    public function has(string $name): bool
    {
        return \array_key_exists($name, $this->attributes);
    }
    public function get(string $name, mixed $default = null): mixed
    {
        return \array_key_exists($name, $this->attributes) ? $this->attributes[$name] : $default;
    }
    public function set(string $name, mixed $value)
    {
        $this->attributes[$name] = $value;
    }
    public function all(): array
    {
        return $this->attributes;
    }
    public function replace(array $attributes)
    {
        $this->attributes = [];
        foreach ($attributes as $key => $value) {
            $this->set($key, $value);
        }
    }
    public function remove(string $name): mixed
    {
        $retval = null;
        if (\array_key_exists($name, $this->attributes)) {
            $retval = $this->attributes[$name];
            unset($this->attributes[$name]);
        }
        return $retval;
    }
    public function clear(): mixed
    {
        $return = $this->attributes;
        $this->attributes = [];
        return $return;
    }
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->attributes);
    }
    public function count(): int
    {
        return \count($this->attributes);
    }
}
}

namespace Symfony\Component\HttpFoundation\Session\Storage {
use Symfony\Component\HttpFoundation\Session\SessionBagInterface;
class MetadataBag implements SessionBagInterface
{
    public const CREATED = 'c';
    public const UPDATED = 'u';
    public const LIFETIME = 'l';
    private string $name = '__metadata';
    private string $storageKey;
    protected $meta = [self::CREATED => 0, self::UPDATED => 0, self::LIFETIME => 0];
    private int $lastUsed;
    private int $updateThreshold;
    public function __construct(string $storageKey = '_sf2_meta', int $updateThreshold = 0)
    {
        $this->storageKey = $storageKey;
        $this->updateThreshold = $updateThreshold;
    }
    public function initialize(array &$array)
    {
        $this->meta =& $array;
        if (isset($array[self::CREATED])) {
            $this->lastUsed = $this->meta[self::UPDATED];
            $timeStamp = time();
            if ($timeStamp - $array[self::UPDATED] >= $this->updateThreshold) {
                $this->meta[self::UPDATED] = $timeStamp;
            }
        } else {
            $this->stampCreated();
        }
    }
    public function getLifetime(): int
    {
        return $this->meta[self::LIFETIME];
    }
    public function stampNew(?int $lifetime = null)
    {
        $this->stampCreated($lifetime);
    }
    public function getStorageKey(): string
    {
        return $this->storageKey;
    }
    public function getCreated(): int
    {
        return $this->meta[self::CREATED];
    }
    public function getLastUsed(): int
    {
        return $this->lastUsed;
    }
    public function clear(): mixed
    {
        return null;
    }
    public function getName(): string
    {
        return $this->name;
    }
    public function setName(string $name)
    {
        $this->name = $name;
    }
    private function stampCreated(?int $lifetime = null): void
    {
        $timeStamp = time();
        $this->meta[self::CREATED] = $this->meta[self::UPDATED] = $this->lastUsed = $timeStamp;
        $this->meta[self::LIFETIME] = $lifetime ?? (int) \ini_get('session.cookie_lifetime');
    }
}
}

namespace Symfony\Component\HttpFoundation {
class AcceptHeaderItem
{
    private string $value;
    private float $quality = 1.0;
    private int $index = 0;
    private array $attributes = [];
    public function __construct(string $value, array $attributes = [])
    {
        $this->value = $value;
        foreach ($attributes as $name => $value) {
            $this->setAttribute($name, $value);
        }
    }
    public static function fromString(?string $itemValue): self
    {
        $parts = HeaderUtils::split($itemValue ?? '', ';=');
        $part = array_shift($parts);
        $attributes = HeaderUtils::combine($parts);
        return new self($part[0], $attributes);
    }
    public function __toString(): string
    {
        $string = $this->value . ($this->quality < 1 ? ';q=' . $this->quality : '');
        if (\count($this->attributes) > 0) {
            $string .= '; ' . HeaderUtils::toString($this->attributes, ';');
        }
        return $string;
    }
    public function setValue(string $value): static
    {
        $this->value = $value;
        return $this;
    }
    public function getValue(): string
    {
        return $this->value;
    }
    public function setQuality(float $quality): static
    {
        $this->quality = $quality;
        return $this;
    }
    public function getQuality(): float
    {
        return $this->quality;
    }
    public function setIndex(int $index): static
    {
        $this->index = $index;
        return $this;
    }
    public function getIndex(): int
    {
        return $this->index;
    }
    public function hasAttribute(string $name): bool
    {
        return isset($this->attributes[$name]);
    }
    public function getAttribute(string $name, mixed $default = null): mixed
    {
        return $this->attributes[$name] ?? $default;
    }
    public function getAttributes(): array
    {
        return $this->attributes;
    }
    public function setAttribute(string $name, string $value): static
    {
        if ('q' === $name) {
            $this->quality = (float) $value;
        } else {
            $this->attributes[$name] = $value;
        }
        return $this;
    }
}
}

namespace Symfony\Component\HttpFoundation {
class_exists(AcceptHeaderItem::class);
class AcceptHeader
{
    private array $items = [];
    private bool $sorted = true;
    public function __construct(array $items)
    {
        foreach ($items as $item) {
            $this->add($item);
        }
    }
    public static function fromString(?string $headerValue): self
    {
        $parts = HeaderUtils::split($headerValue ?? '', ',;=');
        return new self(array_map(function ($subParts) {
            static $index = 0;
            $part = array_shift($subParts);
            $attributes = HeaderUtils::combine($subParts);
            $item = new AcceptHeaderItem($part[0], $attributes);
            $item->setIndex($index++);
            return $item;
        }, $parts));
    }
    public function __toString(): string
    {
        return implode(',', $this->items);
    }
    public function has(string $value): bool
    {
        return isset($this->items[$value]);
    }
    public function get(string $value): ?AcceptHeaderItem
    {
        return $this->items[$value] ?? $this->items[explode('/', $value)[0] . '/*'] ?? $this->items['*/*'] ?? $this->items['*'] ?? null;
    }
    public function add(AcceptHeaderItem $item): static
    {
        $this->items[$item->getValue()] = $item;
        $this->sorted = false;
        return $this;
    }
    public function all(): array
    {
        $this->sort();
        return $this->items;
    }
    public function filter(string $pattern): self
    {
        return new self(array_filter($this->items, fn(AcceptHeaderItem $item) => preg_match($pattern, $item->getValue())));
    }
    public function first(): ?AcceptHeaderItem
    {
        $this->sort();
        return $this->items ? reset($this->items) : null;
    }
    private function sort(): void
    {
        if (!$this->sorted) {
            uasort($this->items, function (AcceptHeaderItem $a, AcceptHeaderItem $b) {
                $qA = $a->getQuality();
                $qB = $b->getQuality();
                if ($qA === $qB) {
                    return $a->getIndex() > $b->getIndex() ? 1 : -1;
                }
                return $qA > $qB ? -1 : 1;
            });
            $this->sorted = true;
        }
    }
}
}

namespace Symfony\Component\HttpFoundation {
class_exists(ResponseHeaderBag::class);
class Response
{
    public const HTTP_CONTINUE = 100;
    public const HTTP_SWITCHING_PROTOCOLS = 101;
    public const HTTP_PROCESSING = 102;
    public const HTTP_EARLY_HINTS = 103;
    public const HTTP_OK = 200;
    public const HTTP_CREATED = 201;
    public const HTTP_ACCEPTED = 202;
    public const HTTP_NON_AUTHORITATIVE_INFORMATION = 203;
    public const HTTP_NO_CONTENT = 204;
    public const HTTP_RESET_CONTENT = 205;
    public const HTTP_PARTIAL_CONTENT = 206;
    public const HTTP_MULTI_STATUS = 207;
    public const HTTP_ALREADY_REPORTED = 208;
    public const HTTP_IM_USED = 226;
    public const HTTP_MULTIPLE_CHOICES = 300;
    public const HTTP_MOVED_PERMANENTLY = 301;
    public const HTTP_FOUND = 302;
    public const HTTP_SEE_OTHER = 303;
    public const HTTP_NOT_MODIFIED = 304;
    public const HTTP_USE_PROXY = 305;
    public const HTTP_RESERVED = 306;
    public const HTTP_TEMPORARY_REDIRECT = 307;
    public const HTTP_PERMANENTLY_REDIRECT = 308;
    public const HTTP_BAD_REQUEST = 400;
    public const HTTP_UNAUTHORIZED = 401;
    public const HTTP_PAYMENT_REQUIRED = 402;
    public const HTTP_FORBIDDEN = 403;
    public const HTTP_NOT_FOUND = 404;
    public const HTTP_METHOD_NOT_ALLOWED = 405;
    public const HTTP_NOT_ACCEPTABLE = 406;
    public const HTTP_PROXY_AUTHENTICATION_REQUIRED = 407;
    public const HTTP_REQUEST_TIMEOUT = 408;
    public const HTTP_CONFLICT = 409;
    public const HTTP_GONE = 410;
    public const HTTP_LENGTH_REQUIRED = 411;
    public const HTTP_PRECONDITION_FAILED = 412;
    public const HTTP_REQUEST_ENTITY_TOO_LARGE = 413;
    public const HTTP_REQUEST_URI_TOO_LONG = 414;
    public const HTTP_UNSUPPORTED_MEDIA_TYPE = 415;
    public const HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416;
    public const HTTP_EXPECTATION_FAILED = 417;
    public const HTTP_I_AM_A_TEAPOT = 418;
    public const HTTP_MISDIRECTED_REQUEST = 421;
    public const HTTP_UNPROCESSABLE_ENTITY = 422;
    public const HTTP_LOCKED = 423;
    public const HTTP_FAILED_DEPENDENCY = 424;
    public const HTTP_TOO_EARLY = 425;
    public const HTTP_UPGRADE_REQUIRED = 426;
    public const HTTP_PRECONDITION_REQUIRED = 428;
    public const HTTP_TOO_MANY_REQUESTS = 429;
    public const HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431;
    public const HTTP_UNAVAILABLE_FOR_LEGAL_REASONS = 451;
    public const HTTP_INTERNAL_SERVER_ERROR = 500;
    public const HTTP_NOT_IMPLEMENTED = 501;
    public const HTTP_BAD_GATEWAY = 502;
    public const HTTP_SERVICE_UNAVAILABLE = 503;
    public const HTTP_GATEWAY_TIMEOUT = 504;
    public const HTTP_VERSION_NOT_SUPPORTED = 505;
    public const HTTP_VARIANT_ALSO_NEGOTIATES_EXPERIMENTAL = 506;
    public const HTTP_INSUFFICIENT_STORAGE = 507;
    public const HTTP_LOOP_DETECTED = 508;
    public const HTTP_NOT_EXTENDED = 510;
    public const HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511;
    private const HTTP_RESPONSE_CACHE_CONTROL_DIRECTIVES = ['must_revalidate' => false, 'no_cache' => false, 'no_store' => false, 'no_transform' => false, 'public' => false, 'private' => false, 'proxy_revalidate' => false, 'max_age' => true, 's_maxage' => true, 'stale_if_error' => true, 'stale_while_revalidate' => true, 'immutable' => false, 'last_modified' => true, 'etag' => true];
    public $headers;
    protected $content;
    protected $version;
    protected $statusCode;
    protected $statusText;
    protected $charset;
    public static $statusTexts = [100 => 'Continue', 101 => 'Switching Protocols', 102 => 'Processing', 103 => 'Early Hints', 200 => 'OK', 201 => 'Created', 202 => 'Accepted', 203 => 'Non-Authoritative Information', 204 => 'No Content', 205 => 'Reset Content', 206 => 'Partial Content', 207 => 'Multi-Status', 208 => 'Already Reported', 226 => 'IM Used', 300 => 'Multiple Choices', 301 => 'Moved Permanently', 302 => 'Found', 303 => 'See Other', 304 => 'Not Modified', 305 => 'Use Proxy', 307 => 'Temporary Redirect', 308 => 'Permanent Redirect', 400 => 'Bad Request', 401 => 'Unauthorized', 402 => 'Payment Required', 403 => 'Forbidden', 404 => 'Not Found', 405 => 'Method Not Allowed', 406 => 'Not Acceptable', 407 => 'Proxy Authentication Required', 408 => 'Request Timeout', 409 => 'Conflict', 410 => 'Gone', 411 => 'Length Required', 412 => 'Precondition Failed', 413 => 'Content Too Large', 414 => 'URI Too Long', 415 => 'Unsupported Media Type', 416 => 'Range Not Satisfiable', 417 => 'Expectation Failed', 418 => 'I\'m a teapot', 421 => 'Misdirected Request', 422 => 'Unprocessable Content', 423 => 'Locked', 424 => 'Failed Dependency', 425 => 'Too Early', 426 => 'Upgrade Required', 428 => 'Precondition Required', 429 => 'Too Many Requests', 431 => 'Request Header Fields Too Large', 451 => 'Unavailable For Legal Reasons', 500 => 'Internal Server Error', 501 => 'Not Implemented', 502 => 'Bad Gateway', 503 => 'Service Unavailable', 504 => 'Gateway Timeout', 505 => 'HTTP Version Not Supported', 506 => 'Variant Also Negotiates', 507 => 'Insufficient Storage', 508 => 'Loop Detected', 510 => 'Not Extended', 511 => 'Network Authentication Required'];
    private array $sentHeaders;
    public function __construct(?string $content = '', int $status = 200, array $headers = [])
    {
        $this->headers = new ResponseHeaderBag($headers);
        $this->setContent($content);
        $this->setStatusCode($status);
        $this->setProtocolVersion('1.0');
    }
    public function __toString(): string
    {
        return sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText) . "\r\n" . $this->headers . "\r\n" . $this->getContent();
    }
    public function __clone()
    {
        $this->headers = clone $this->headers;
    }
    public function prepare(Request $request): static
    {
        $headers = $this->headers;
        if ($this->isInformational() || $this->isEmpty()) {
            $this->setContent(null);
            $headers->remove('Content-Type');
            $headers->remove('Content-Length');
            ini_set('default_mimetype', '');
        } else {
            if (!$headers->has('Content-Type')) {
                $format = $request->getRequestFormat(null);
                if (null !== $format && $mimeType = $request->getMimeType($format)) {
                    $headers->set('Content-Type', $mimeType);
                }
            }
            $charset = $this->charset ?: 'UTF-8';
            if (!$headers->has('Content-Type')) {
                $headers->set('Content-Type', 'text/html; charset=' . $charset);
            } elseif (0 === stripos($headers->get('Content-Type') ?? '', 'text/') && false === stripos($headers->get('Content-Type') ?? '', 'charset')) {
                $headers->set('Content-Type', $headers->get('Content-Type') . '; charset=' . $charset);
            }
            if ($headers->has('Transfer-Encoding')) {
                $headers->remove('Content-Length');
            }
            if ($request->isMethod('HEAD')) {
                $length = $headers->get('Content-Length');
                $this->setContent(null);
                if ($length) {
                    $headers->set('Content-Length', $length);
                }
            }
        }
        if ('HTTP/1.0' != $request->server->get('SERVER_PROTOCOL')) {
            $this->setProtocolVersion('1.1');
        }
        if ('1.0' == $this->getProtocolVersion() && str_contains($headers->get('Cache-Control', ''), 'no-cache')) {
            $headers->set('pragma', 'no-cache');
            $headers->set('expires', -1);
        }
        $this->ensureIEOverSSLCompatibility($request);
        if ($request->isSecure()) {
            foreach ($headers->getCookies() as $cookie) {
                $cookie->setSecureDefault(true);
            }
        }
        return $this;
    }
    public function sendHeaders(): static
    {
        if (headers_sent()) {
            return $this;
        }
        $statusCode = \func_num_args() > 0 ? func_get_arg(0) : null;
        $informationalResponse = $statusCode >= 100 && $statusCode < 200;
        if ($informationalResponse && !\function_exists('headers_send')) {
            return $this;
        }
        foreach ($this->headers->allPreserveCaseWithoutCookies() as $name => $values) {
            $newValues = $values;
            $replace = false;
            $previousValues = $this->sentHeaders[$name] ?? null;
            if ($previousValues === $values) {
                continue;
            }
            $replace = 0 === strcasecmp($name, 'Content-Type');
            if (null !== $previousValues && array_diff($previousValues, $values)) {
                header_remove($name);
                $previousValues = null;
            }
            $newValues = null === $previousValues ? $values : array_diff($values, $previousValues);
            foreach ($newValues as $value) {
                header($name . ': ' . $value, $replace, $this->statusCode);
            }
            if ($informationalResponse) {
                $this->sentHeaders[$name] = $values;
            }
        }
        foreach ($this->headers->getCookies() as $cookie) {
            header('Set-Cookie: ' . $cookie, false, $this->statusCode);
        }
        if ($informationalResponse) {
            headers_send($statusCode);
            return $this;
        }
        $statusCode ??= $this->statusCode;
        header(sprintf('HTTP/%s %s %s', $this->version, $statusCode, $this->statusText), true, $statusCode);
        return $this;
    }
    public function sendContent(): static
    {
        echo $this->content;
        return $this;
    }
    public function send(): static
    {
        $this->sendHeaders();
        $this->sendContent();
        $flush = 1 <= \func_num_args() ? func_get_arg(0) : true;
        if (!$flush) {
            return $this;
        }
        if (\function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        } elseif (\function_exists('litespeed_finish_request')) {
            litespeed_finish_request();
        } elseif (!\in_array(\PHP_SAPI, ['cli', 'phpdbg', 'embed'], true)) {
            static::closeOutputBuffers(0, true);
            flush();
        }
        return $this;
    }
    public function setContent(?string $content): static
    {
        $this->content = $content ?? '';
        return $this;
    }
    public function getContent(): string|false
    {
        return $this->content;
    }
    public function setProtocolVersion(string $version): static
    {
        $this->version = $version;
        return $this;
    }
    public function getProtocolVersion(): string
    {
        return $this->version;
    }
    public function setStatusCode(int $code, ?string $text = null): static
    {
        $this->statusCode = $code;
        if ($this->isInvalid()) {
            throw new \InvalidArgumentException(sprintf('The HTTP status code "%s" is not valid.', $code));
        }
        if (null === $text) {
            $this->statusText = self::$statusTexts[$code] ?? 'unknown status';
            return $this;
        }
        $this->statusText = $text;
        return $this;
    }
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
    public function setCharset(string $charset): static
    {
        $this->charset = $charset;
        return $this;
    }
    public function getCharset(): ?string
    {
        return $this->charset;
    }
    public function isCacheable(): bool
    {
        if (!\in_array($this->statusCode, [200, 203, 300, 301, 302, 404, 410])) {
            return false;
        }
        if ($this->headers->hasCacheControlDirective('no-store') || $this->headers->getCacheControlDirective('private')) {
            return false;
        }
        return $this->isValidateable() || $this->isFresh();
    }
    public function isFresh(): bool
    {
        return $this->getTtl() > 0;
    }
    public function isValidateable(): bool
    {
        return $this->headers->has('Last-Modified') || $this->headers->has('ETag');
    }
    public function setPrivate(): static
    {
        $this->headers->removeCacheControlDirective('public');
        $this->headers->addCacheControlDirective('private');
        return $this;
    }
    public function setPublic(): static
    {
        $this->headers->addCacheControlDirective('public');
        $this->headers->removeCacheControlDirective('private');
        return $this;
    }
    public function setImmutable(bool $immutable = true): static
    {
        if ($immutable) {
            $this->headers->addCacheControlDirective('immutable');
        } else {
            $this->headers->removeCacheControlDirective('immutable');
        }
        return $this;
    }
    public function isImmutable(): bool
    {
        return $this->headers->hasCacheControlDirective('immutable');
    }
    public function mustRevalidate(): bool
    {
        return $this->headers->hasCacheControlDirective('must-revalidate') || $this->headers->hasCacheControlDirective('proxy-revalidate');
    }
    public function getDate(): ?\DateTimeImmutable
    {
        return $this->headers->getDate('Date');
    }
    public function setDate(\DateTimeInterface $date): static
    {
        $date = \DateTimeImmutable::createFromInterface($date);
        $date = $date->setTimezone(new \DateTimeZone('UTC'));
        $this->headers->set('Date', $date->format('D, d M Y H:i:s') . ' GMT');
        return $this;
    }
    public function getAge(): int
    {
        if (null !== $age = $this->headers->get('Age')) {
            return (int) $age;
        }
        return max(time() - (int) $this->getDate()->format('U'), 0);
    }
    public function expire(): static
    {
        if ($this->isFresh()) {
            $this->headers->set('Age', $this->getMaxAge());
            $this->headers->remove('Expires');
        }
        return $this;
    }
    public function getExpires(): ?\DateTimeImmutable
    {
        try {
            return $this->headers->getDate('Expires');
        } catch (\RuntimeException) {
            return \DateTimeImmutable::createFromFormat('U', time() - 172800);
        }
    }
    public function setExpires(?\DateTimeInterface $date = null): static
    {
        if (1 > \func_num_args()) {
            trigger_deprecation('symfony/http-foundation', '6.2', 'Calling "%s()" without any arguments is deprecated, pass null explicitly instead.', __METHOD__);
        }
        if (null === $date) {
            $this->headers->remove('Expires');
            return $this;
        }
        $date = \DateTimeImmutable::createFromInterface($date);
        $date = $date->setTimezone(new \DateTimeZone('UTC'));
        $this->headers->set('Expires', $date->format('D, d M Y H:i:s') . ' GMT');
        return $this;
    }
    public function getMaxAge(): ?int
    {
        if ($this->headers->hasCacheControlDirective('s-maxage')) {
            return (int) $this->headers->getCacheControlDirective('s-maxage');
        }
        if ($this->headers->hasCacheControlDirective('max-age')) {
            return (int) $this->headers->getCacheControlDirective('max-age');
        }
        if (null !== $expires = $this->getExpires()) {
            $maxAge = (int) $expires->format('U') - (int) $this->getDate()->format('U');
            return max($maxAge, 0);
        }
        return null;
    }
    public function setMaxAge(int $value): static
    {
        $this->headers->addCacheControlDirective('max-age', $value);
        return $this;
    }
    public function setStaleIfError(int $value): static
    {
        $this->headers->addCacheControlDirective('stale-if-error', $value);
        return $this;
    }
    public function setStaleWhileRevalidate(int $value): static
    {
        $this->headers->addCacheControlDirective('stale-while-revalidate', $value);
        return $this;
    }
    public function setSharedMaxAge(int $value): static
    {
        $this->setPublic();
        $this->headers->addCacheControlDirective('s-maxage', $value);
        return $this;
    }
    public function getTtl(): ?int
    {
        $maxAge = $this->getMaxAge();
        return null !== $maxAge ? max($maxAge - $this->getAge(), 0) : null;
    }
    public function setTtl(int $seconds): static
    {
        $this->setSharedMaxAge($this->getAge() + $seconds);
        return $this;
    }
    public function setClientTtl(int $seconds): static
    {
        $this->setMaxAge($this->getAge() + $seconds);
        return $this;
    }
    public function getLastModified(): ?\DateTimeImmutable
    {
        return $this->headers->getDate('Last-Modified');
    }
    public function setLastModified(?\DateTimeInterface $date = null): static
    {
        if (1 > \func_num_args()) {
            trigger_deprecation('symfony/http-foundation', '6.2', 'Calling "%s()" without any arguments is deprecated, pass null explicitly instead.', __METHOD__);
        }
        if (null === $date) {
            $this->headers->remove('Last-Modified');
            return $this;
        }
        $date = \DateTimeImmutable::createFromInterface($date);
        $date = $date->setTimezone(new \DateTimeZone('UTC'));
        $this->headers->set('Last-Modified', $date->format('D, d M Y H:i:s') . ' GMT');
        return $this;
    }
    public function getEtag(): ?string
    {
        return $this->headers->get('ETag');
    }
    public function setEtag(?string $etag = null, bool $weak = false): static
    {
        if (1 > \func_num_args()) {
            trigger_deprecation('symfony/http-foundation', '6.2', 'Calling "%s()" without any arguments is deprecated, pass null explicitly instead.', __METHOD__);
        }
        if (null === $etag) {
            $this->headers->remove('Etag');
        } else {
            if (!str_starts_with($etag, '"')) {
                $etag = '"' . $etag . '"';
            }
            $this->headers->set('ETag', (true === $weak ? 'W/' : '') . $etag);
        }
        return $this;
    }
    public function setCache(array $options): static
    {
        if ($diff = array_diff(array_keys($options), array_keys(self::HTTP_RESPONSE_CACHE_CONTROL_DIRECTIVES))) {
            throw new \InvalidArgumentException(sprintf('Response does not support the following options: "%s".', implode('", "', $diff)));
        }
        if (isset($options['etag'])) {
            $this->setEtag($options['etag']);
        }
        if (isset($options['last_modified'])) {
            $this->setLastModified($options['last_modified']);
        }
        if (isset($options['max_age'])) {
            $this->setMaxAge($options['max_age']);
        }
        if (isset($options['s_maxage'])) {
            $this->setSharedMaxAge($options['s_maxage']);
        }
        if (isset($options['stale_while_revalidate'])) {
            $this->setStaleWhileRevalidate($options['stale_while_revalidate']);
        }
        if (isset($options['stale_if_error'])) {
            $this->setStaleIfError($options['stale_if_error']);
        }
        foreach (self::HTTP_RESPONSE_CACHE_CONTROL_DIRECTIVES as $directive => $hasValue) {
            if (!$hasValue && isset($options[$directive])) {
                if ($options[$directive]) {
                    $this->headers->addCacheControlDirective(str_replace('_', '-', $directive));
                } else {
                    $this->headers->removeCacheControlDirective(str_replace('_', '-', $directive));
                }
            }
        }
        if (isset($options['public'])) {
            if ($options['public']) {
                $this->setPublic();
            } else {
                $this->setPrivate();
            }
        }
        if (isset($options['private'])) {
            if ($options['private']) {
                $this->setPrivate();
            } else {
                $this->setPublic();
            }
        }
        return $this;
    }
    public function setNotModified(): static
    {
        $this->setStatusCode(304);
        $this->setContent(null);
        foreach (['Allow', 'Content-Encoding', 'Content-Language', 'Content-Length', 'Content-MD5', 'Content-Type', 'Last-Modified'] as $header) {
            $this->headers->remove($header);
        }
        return $this;
    }
    public function hasVary(): bool
    {
        return null !== $this->headers->get('Vary');
    }
    public function getVary(): array
    {
        if (!$vary = $this->headers->all('Vary')) {
            return [];
        }
        $ret = [];
        foreach ($vary as $item) {
            $ret[] = preg_split('/[\s,]+/', $item);
        }
        return array_merge([], ...$ret);
    }
    public function setVary(string|array $headers, bool $replace = true): static
    {
        $this->headers->set('Vary', $headers, $replace);
        return $this;
    }
    public function isNotModified(Request $request): bool
    {
        if (!$request->isMethodCacheable()) {
            return false;
        }
        $notModified = false;
        $lastModified = $this->headers->get('Last-Modified');
        $modifiedSince = $request->headers->get('If-Modified-Since');
        if (($ifNoneMatchEtags = $request->getETags()) && null !== $etag = $this->getEtag()) {
            if (0 == strncmp($etag, 'W/', 2)) {
                $etag = substr($etag, 2);
            }
            foreach ($ifNoneMatchEtags as $ifNoneMatchEtag) {
                if (0 == strncmp($ifNoneMatchEtag, 'W/', 2)) {
                    $ifNoneMatchEtag = substr($ifNoneMatchEtag, 2);
                }
                if ($ifNoneMatchEtag === $etag || '*' === $ifNoneMatchEtag) {
                    $notModified = true;
                    break;
                }
            }
        } elseif ($modifiedSince && $lastModified) {
            $notModified = strtotime($modifiedSince) >= strtotime($lastModified);
        }
        if ($notModified) {
            $this->setNotModified();
        }
        return $notModified;
    }
    public function isInvalid(): bool
    {
        return $this->statusCode < 100 || $this->statusCode >= 600;
    }
    public function isInformational(): bool
    {
        return $this->statusCode >= 100 && $this->statusCode < 200;
    }
    public function isSuccessful(): bool
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }
    public function isRedirection(): bool
    {
        return $this->statusCode >= 300 && $this->statusCode < 400;
    }
    public function isClientError(): bool
    {
        return $this->statusCode >= 400 && $this->statusCode < 500;
    }
    public function isServerError(): bool
    {
        return $this->statusCode >= 500 && $this->statusCode < 600;
    }
    public function isOk(): bool
    {
        return 200 === $this->statusCode;
    }
    public function isForbidden(): bool
    {
        return 403 === $this->statusCode;
    }
    public function isNotFound(): bool
    {
        return 404 === $this->statusCode;
    }
    public function isRedirect(?string $location = null): bool
    {
        return \in_array($this->statusCode, [201, 301, 302, 303, 307, 308]) && (null === $location ?: $location == $this->headers->get('Location'));
    }
    public function isEmpty(): bool
    {
        return \in_array($this->statusCode, [204, 304]);
    }
    public static function closeOutputBuffers(int $targetLevel, bool $flush): void
    {
        $status = ob_get_status(true);
        $level = \count($status);
        $flags = \PHP_OUTPUT_HANDLER_REMOVABLE | ($flush ? \PHP_OUTPUT_HANDLER_FLUSHABLE : \PHP_OUTPUT_HANDLER_CLEANABLE);
        while ($level-- > $targetLevel && ($s = $status[$level]) && (!isset($s['del']) ? !isset($s['flags']) || ($s['flags'] & $flags) === $flags : $s['del'])) {
            if ($flush) {
                ob_end_flush();
            } else {
                ob_end_clean();
            }
        }
    }
    public function setContentSafe(bool $safe = true): void
    {
        if ($safe) {
            $this->headers->set('Preference-Applied', 'safe');
        } elseif ('safe' === $this->headers->get('Preference-Applied')) {
            $this->headers->remove('Preference-Applied');
        }
        $this->setVary('Prefer', false);
    }
    protected function ensureIEOverSSLCompatibility(Request $request): void
    {
        if (false !== stripos($this->headers->get('Content-Disposition') ?? '', 'attachment') && 1 == preg_match('/MSIE (.*?);/i', $request->server->get('HTTP_USER_AGENT') ?? '', $match) && true === $request->isSecure()) {
            if ((int) preg_replace('/(MSIE )(.*?);/', '$2', $match[0]) < 9) {
                $this->headers->remove('Cache-Control');
            }
        }
    }
}
}

namespace Symfony\Component\HttpFoundation {
class ResponseHeaderBag extends HeaderBag
{
    public const COOKIES_FLAT = 'flat';
    public const COOKIES_ARRAY = 'array';
    public const DISPOSITION_ATTACHMENT = 'attachment';
    public const DISPOSITION_INLINE = 'inline';
    protected $computedCacheControl = [];
    protected $cookies = [];
    protected $headerNames = [];
    public function __construct(array $headers = [])
    {
        parent::__construct($headers);
        if (!isset($this->headers['cache-control'])) {
            $this->set('Cache-Control', '');
        }
        if (!isset($this->headers['date'])) {
            $this->initDate();
        }
    }
    public function allPreserveCase(): array
    {
        $headers = [];
        foreach ($this->all() as $name => $value) {
            $headers[$this->headerNames[$name] ?? $name] = $value;
        }
        return $headers;
    }
    public function allPreserveCaseWithoutCookies()
    {
        $headers = $this->allPreserveCase();
        if (isset($this->headerNames['set-cookie'])) {
            unset($headers[$this->headerNames['set-cookie']]);
        }
        return $headers;
    }
    public function replace(array $headers = [])
    {
        $this->headerNames = [];
        parent::replace($headers);
        if (!isset($this->headers['cache-control'])) {
            $this->set('Cache-Control', '');
        }
        if (!isset($this->headers['date'])) {
            $this->initDate();
        }
    }
    public function all(?string $key = null): array
    {
        $headers = parent::all();
        if (null !== $key) {
            $key = strtr($key, self::UPPER, self::LOWER);
            return 'set-cookie' !== $key ? $headers[$key] ?? [] : array_map('strval', $this->getCookies());
        }
        foreach ($this->getCookies() as $cookie) {
            $headers['set-cookie'][] = (string) $cookie;
        }
        return $headers;
    }
    public function set(string $key, string|array|null $values, bool $replace = true)
    {
        $uniqueKey = strtr($key, self::UPPER, self::LOWER);
        if ('set-cookie' === $uniqueKey) {
            if ($replace) {
                $this->cookies = [];
            }
            foreach ((array) $values as $cookie) {
                $this->setCookie(Cookie::fromString($cookie));
            }
            $this->headerNames[$uniqueKey] = $key;
            return;
        }
        $this->headerNames[$uniqueKey] = $key;
        parent::set($key, $values, $replace);
        if (\in_array($uniqueKey, ['cache-control', 'etag', 'last-modified', 'expires'], true) && '' !== $computed = $this->computeCacheControlValue()) {
            $this->headers['cache-control'] = [$computed];
            $this->headerNames['cache-control'] = 'Cache-Control';
            $this->computedCacheControl = $this->parseCacheControl($computed);
        }
    }
    public function remove(string $key)
    {
        $uniqueKey = strtr($key, self::UPPER, self::LOWER);
        unset($this->headerNames[$uniqueKey]);
        if ('set-cookie' === $uniqueKey) {
            $this->cookies = [];
            return;
        }
        parent::remove($key);
        if ('cache-control' === $uniqueKey) {
            $this->computedCacheControl = [];
        }
        if ('date' === $uniqueKey) {
            $this->initDate();
        }
    }
    public function hasCacheControlDirective(string $key): bool
    {
        return \array_key_exists($key, $this->computedCacheControl);
    }
    public function getCacheControlDirective(string $key): bool|string|null
    {
        return $this->computedCacheControl[$key] ?? null;
    }
    public function setCookie(Cookie $cookie)
    {
        $this->cookies[$cookie->getDomain()][$cookie->getPath()][$cookie->getName()] = $cookie;
        $this->headerNames['set-cookie'] = 'Set-Cookie';
    }
    public function removeCookie(string $name, ?string $path = '/', ?string $domain = null)
    {
        $path ??= '/';
        unset($this->cookies[$domain][$path][$name]);
        if (empty($this->cookies[$domain][$path])) {
            unset($this->cookies[$domain][$path]);
            if (empty($this->cookies[$domain])) {
                unset($this->cookies[$domain]);
            }
        }
        if (empty($this->cookies)) {
            unset($this->headerNames['set-cookie']);
        }
    }
    public function getCookies(string $format = self::COOKIES_FLAT): array
    {
        if (!\in_array($format, [self::COOKIES_FLAT, self::COOKIES_ARRAY])) {
            throw new \InvalidArgumentException(sprintf('Format "%s" invalid (%s).', $format, implode(', ', [self::COOKIES_FLAT, self::COOKIES_ARRAY])));
        }
        if (self::COOKIES_ARRAY === $format) {
            return $this->cookies;
        }
        $flattenedCookies = [];
        foreach ($this->cookies as $path) {
            foreach ($path as $cookies) {
                foreach ($cookies as $cookie) {
                    $flattenedCookies[] = $cookie;
                }
            }
        }
        return $flattenedCookies;
    }
    public function clearCookie(string $name, ?string $path = '/', ?string $domain = null, bool $secure = false, bool $httpOnly = true, ?string $sameSite = null)
    {
        $partitioned = 6 < \func_num_args() ? \func_get_arg(6) : false;
        $this->setCookie(new Cookie($name, null, 1, $path, $domain, $secure, $httpOnly, false, $sameSite, $partitioned));
    }
    public function makeDisposition(string $disposition, string $filename, string $filenameFallback = '')
    {
        return HeaderUtils::makeDisposition($disposition, $filename, $filenameFallback);
    }
    protected function computeCacheControlValue(): string
    {
        if (!$this->cacheControl) {
            if ($this->has('Last-Modified') || $this->has('Expires')) {
                return 'private, must-revalidate';
            }
            return 'no-cache, private';
        }
        $header = $this->getCacheControlHeader();
        if (isset($this->cacheControl['public']) || isset($this->cacheControl['private'])) {
            return $header;
        }
        if (!isset($this->cacheControl['s-maxage'])) {
            return $header . ', private';
        }
        return $header;
    }
    private function initDate(): void
    {
        $this->set('Date', gmdate('D, d M Y H:i:s') . ' GMT');
    }
}
}

namespace Symfony\Component\HttpFoundation {
class Cookie
{
    public const SAMESITE_NONE = 'none';
    public const SAMESITE_LAX = 'lax';
    public const SAMESITE_STRICT = 'strict';
    protected $name;
    protected $value;
    protected $domain;
    protected $expire;
    protected $path;
    protected $secure;
    protected $httpOnly;
    private bool $raw;
    private ?string $sameSite = null;
    private bool $partitioned = false;
    private bool $secureDefault = false;
    private const RESERVED_CHARS_LIST = "=,; \t\r\n\v\f";
    private const RESERVED_CHARS_FROM = ['=', ',', ';', ' ', "\t", "\r", "\n", "\v", "\f"];
    private const RESERVED_CHARS_TO = ['%3D', '%2C', '%3B', '%20', '%09', '%0D', '%0A', '%0B', '%0C'];
    public static function fromString(string $cookie, bool $decode = false): static
    {
        $data = ['expires' => 0, 'path' => '/', 'domain' => null, 'secure' => false, 'httponly' => false, 'raw' => !$decode, 'samesite' => null, 'partitioned' => false];
        $parts = HeaderUtils::split($cookie, ';=');
        $part = array_shift($parts);
        $name = $decode ? urldecode($part[0]) : $part[0];
        $value = isset($part[1]) ? $decode ? urldecode($part[1]) : $part[1] : null;
        $data = HeaderUtils::combine($parts) + $data;
        $data['expires'] = self::expiresTimestamp($data['expires']);
        if (isset($data['max-age']) && ($data['max-age'] > 0 || $data['expires'] > time())) {
            $data['expires'] = time() + (int) $data['max-age'];
        }
        return new static($name, $value, $data['expires'], $data['path'], $data['domain'], $data['secure'], $data['httponly'], $data['raw'], $data['samesite'], $data['partitioned']);
    }
    public static function create(string $name, ?string $value = null, int|string|\DateTimeInterface $expire = 0, ?string $path = '/', ?string $domain = null, ?bool $secure = null, bool $httpOnly = true, bool $raw = false, ?string $sameSite = self::SAMESITE_LAX): self
    {
        $partitioned = 9 < \func_num_args() ? func_get_arg(9) : false;
        return new self($name, $value, $expire, $path, $domain, $secure, $httpOnly, $raw, $sameSite, $partitioned);
    }
    public function __construct(string $name, ?string $value = null, int|string|\DateTimeInterface $expire = 0, ?string $path = '/', ?string $domain = null, ?bool $secure = null, bool $httpOnly = true, bool $raw = false, ?string $sameSite = self::SAMESITE_LAX, bool $partitioned = false)
    {
        if ($raw && false !== strpbrk($name, self::RESERVED_CHARS_LIST)) {
            throw new \InvalidArgumentException(sprintf('The cookie name "%s" contains invalid characters.', $name));
        }
        if (empty($name)) {
            throw new \InvalidArgumentException('The cookie name cannot be empty.');
        }
        $this->name = $name;
        $this->value = $value;
        $this->domain = $domain;
        $this->expire = self::expiresTimestamp($expire);
        $this->path = empty($path) ? '/' : $path;
        $this->secure = $secure;
        $this->httpOnly = $httpOnly;
        $this->raw = $raw;
        $this->sameSite = $this->withSameSite($sameSite)->sameSite;
        $this->partitioned = $partitioned;
    }
    public function withValue(?string $value): static
    {
        $cookie = clone $this;
        $cookie->value = $value;
        return $cookie;
    }
    public function withDomain(?string $domain): static
    {
        $cookie = clone $this;
        $cookie->domain = $domain;
        return $cookie;
    }
    public function withExpires(int|string|\DateTimeInterface $expire = 0): static
    {
        $cookie = clone $this;
        $cookie->expire = self::expiresTimestamp($expire);
        return $cookie;
    }
    private static function expiresTimestamp(int|string|\DateTimeInterface $expire = 0): int
    {
        if ($expire instanceof \DateTimeInterface) {
            $expire = $expire->format('U');
        } elseif (!is_numeric($expire)) {
            $expire = strtotime($expire);
            if (false === $expire) {
                throw new \InvalidArgumentException('The cookie expiration time is not valid.');
            }
        }
        return 0 < $expire ? (int) $expire : 0;
    }
    public function withPath(string $path): static
    {
        $cookie = clone $this;
        $cookie->path = '' === $path ? '/' : $path;
        return $cookie;
    }
    public function withSecure(bool $secure = true): static
    {
        $cookie = clone $this;
        $cookie->secure = $secure;
        return $cookie;
    }
    public function withHttpOnly(bool $httpOnly = true): static
    {
        $cookie = clone $this;
        $cookie->httpOnly = $httpOnly;
        return $cookie;
    }
    public function withRaw(bool $raw = true): static
    {
        if ($raw && false !== strpbrk($this->name, self::RESERVED_CHARS_LIST)) {
            throw new \InvalidArgumentException(sprintf('The cookie name "%s" contains invalid characters.', $this->name));
        }
        $cookie = clone $this;
        $cookie->raw = $raw;
        return $cookie;
    }
    public function withSameSite(?string $sameSite): static
    {
        if ('' === $sameSite) {
            $sameSite = null;
        } elseif (null !== $sameSite) {
            $sameSite = strtolower($sameSite);
        }
        if (!\in_array($sameSite, [self::SAMESITE_LAX, self::SAMESITE_STRICT, self::SAMESITE_NONE, null], true)) {
            throw new \InvalidArgumentException('The "sameSite" parameter value is not valid.');
        }
        $cookie = clone $this;
        $cookie->sameSite = $sameSite;
        return $cookie;
    }
    public function withPartitioned(bool $partitioned = true): static
    {
        $cookie = clone $this;
        $cookie->partitioned = $partitioned;
        return $cookie;
    }
    public function __toString(): string
    {
        if ($this->isRaw()) {
            $str = $this->getName();
        } else {
            $str = str_replace(self::RESERVED_CHARS_FROM, self::RESERVED_CHARS_TO, $this->getName());
        }
        $str .= '=';
        if ('' === (string) $this->getValue()) {
            $str .= 'deleted; expires=' . gmdate('D, d M Y H:i:s T', time() - 31536001) . '; Max-Age=0';
        } else {
            $str .= $this->isRaw() ? $this->getValue() : rawurlencode($this->getValue());
            if (0 !== $this->getExpiresTime()) {
                $str .= '; expires=' . gmdate('D, d M Y H:i:s T', $this->getExpiresTime()) . '; Max-Age=' . $this->getMaxAge();
            }
        }
        if ($this->getPath()) {
            $str .= '; path=' . $this->getPath();
        }
        if ($this->getDomain()) {
            $str .= '; domain=' . $this->getDomain();
        }
        if ($this->isSecure()) {
            $str .= '; secure';
        }
        if ($this->isHttpOnly()) {
            $str .= '; httponly';
        }
        if (null !== $this->getSameSite()) {
            $str .= '; samesite=' . $this->getSameSite();
        }
        if ($this->isPartitioned()) {
            $str .= '; partitioned';
        }
        return $str;
    }
    public function getName(): string
    {
        return $this->name;
    }
    public function getValue(): ?string
    {
        return $this->value;
    }
    public function getDomain(): ?string
    {
        return $this->domain;
    }
    public function getExpiresTime(): int
    {
        return $this->expire;
    }
    public function getMaxAge(): int
    {
        $maxAge = $this->expire - time();
        return 0 >= $maxAge ? 0 : $maxAge;
    }
    public function getPath(): string
    {
        return $this->path;
    }
    public function isSecure(): bool
    {
        return $this->secure ?? $this->secureDefault;
    }
    public function isHttpOnly(): bool
    {
        return $this->httpOnly;
    }
    public function isCleared(): bool
    {
        return 0 !== $this->expire && $this->expire < time();
    }
    public function isRaw(): bool
    {
        return $this->raw;
    }
    public function isPartitioned(): bool
    {
        return $this->partitioned;
    }
    public function getSameSite(): ?string
    {
        return $this->sameSite;
    }
    public function setSecureDefault(bool $default): void
    {
        $this->secureDefault = $default;
    }
}
}

namespace Illuminate\Support {
use Closure;
use Illuminate\Console\Application as Artisan;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Contracts\Foundation\CachesRoutes;
use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Database\Eloquent\Factory as ModelFactory;
use Illuminate\View\Compilers\BladeCompiler;
abstract class ServiceProvider
{
    protected $app;
    protected $bootingCallbacks = [];
    protected $bootedCallbacks = [];
    public static $publishes = [];
    public static $publishGroups = [];
    public function __construct($app)
    {
        $this->app = $app;
    }
    public function register()
    {
    }
    public function booting(Closure $callback)
    {
        $this->bootingCallbacks[] = $callback;
    }
    public function booted(Closure $callback)
    {
        $this->bootedCallbacks[] = $callback;
    }
    public function callBootingCallbacks()
    {
        $index = 0;
        while ($index < count($this->bootingCallbacks)) {
            $this->app->call($this->bootingCallbacks[$index]);
            $index++;
        }
    }
    public function callBootedCallbacks()
    {
        $index = 0;
        while ($index < count($this->bootedCallbacks)) {
            $this->app->call($this->bootedCallbacks[$index]);
            $index++;
        }
    }
    protected function mergeConfigFrom($path, $key)
    {
        if (!($this->app instanceof CachesConfiguration && $this->app->configurationIsCached())) {
            $config = $this->app->make('config');
            $config->set($key, array_merge(require $path, $config->get($key, [])));
        }
    }
    protected function loadRoutesFrom($path)
    {
        if (!($this->app instanceof CachesRoutes && $this->app->routesAreCached())) {
            require $path;
        }
    }
    protected function loadViewsFrom($path, $namespace)
    {
        $this->callAfterResolving('view', function ($view) use ($path, $namespace) {
            if (isset($this->app->config['view']['paths']) && is_array($this->app->config['view']['paths'])) {
                foreach ($this->app->config['view']['paths'] as $viewPath) {
                    if (is_dir($appPath = $viewPath . '/vendor/' . $namespace)) {
                        $view->addNamespace($namespace, $appPath);
                    }
                }
            }
            $view->addNamespace($namespace, $path);
        });
    }
    protected function loadViewComponentsAs($prefix, array $components)
    {
        $this->callAfterResolving(BladeCompiler::class, function ($blade) use ($prefix, $components) {
            foreach ($components as $alias => $component) {
                $blade->component($component, is_string($alias) ? $alias : null, $prefix);
            }
        });
    }
    protected function loadTranslationsFrom($path, $namespace)
    {
        $this->callAfterResolving('translator', function ($translator) use ($path, $namespace) {
            $translator->addNamespace($namespace, $path);
        });
    }
    protected function loadJsonTranslationsFrom($path)
    {
        $this->callAfterResolving('translator', function ($translator) use ($path) {
            $translator->addJsonPath($path);
        });
    }
    protected function loadMigrationsFrom($paths)
    {
        $this->callAfterResolving('migrator', function ($migrator) use ($paths) {
            foreach ((array) $paths as $path) {
                $migrator->path($path);
            }
        });
    }
    protected function loadFactoriesFrom($paths)
    {
        $this->callAfterResolving(ModelFactory::class, function ($factory) use ($paths) {
            foreach ((array) $paths as $path) {
                $factory->load($path);
            }
        });
    }
    protected function callAfterResolving($name, $callback)
    {
        $this->app->afterResolving($name, $callback);
        if ($this->app->resolved($name)) {
            $callback($this->app->make($name), $this->app);
        }
    }
    protected function publishes(array $paths, $groups = null)
    {
        $this->ensurePublishArrayInitialized($class = static::class);
        static::$publishes[$class] = array_merge(static::$publishes[$class], $paths);
        foreach ((array) $groups as $group) {
            $this->addPublishGroup($group, $paths);
        }
    }
    protected function ensurePublishArrayInitialized($class)
    {
        if (!array_key_exists($class, static::$publishes)) {
            static::$publishes[$class] = [];
        }
    }
    protected function addPublishGroup($group, $paths)
    {
        if (!array_key_exists($group, static::$publishGroups)) {
            static::$publishGroups[$group] = [];
        }
        static::$publishGroups[$group] = array_merge(static::$publishGroups[$group], $paths);
    }
    public static function pathsToPublish($provider = null, $group = null)
    {
        if (!is_null($paths = static::pathsForProviderOrGroup($provider, $group))) {
            return $paths;
        }
        return collect(static::$publishes)->reduce(function ($paths, $p) {
            return array_merge($paths, $p);
        }, []);
    }
    protected static function pathsForProviderOrGroup($provider, $group)
    {
        if ($provider && $group) {
            return static::pathsForProviderAndGroup($provider, $group);
        } elseif ($group && array_key_exists($group, static::$publishGroups)) {
            return static::$publishGroups[$group];
        } elseif ($provider && array_key_exists($provider, static::$publishes)) {
            return static::$publishes[$provider];
        } elseif ($group || $provider) {
            return [];
        }
    }
    protected static function pathsForProviderAndGroup($provider, $group)
    {
        if (!empty(static::$publishes[$provider]) && !empty(static::$publishGroups[$group])) {
            return array_intersect_key(static::$publishes[$provider], static::$publishGroups[$group]);
        }
        return [];
    }
    public static function publishableProviders()
    {
        return array_keys(static::$publishes);
    }
    public static function publishableGroups()
    {
        return array_keys(static::$publishGroups);
    }
    public function commands($commands)
    {
        $commands = is_array($commands) ? $commands : func_get_args();
        Artisan::starting(function ($artisan) use ($commands) {
            $artisan->resolveCommands($commands);
        });
    }
    public function provides()
    {
        return [];
    }
    public function when()
    {
        return [];
    }
    public function isDeferred()
    {
        return $this instanceof DeferrableProvider;
    }
    public static function defaultProviders()
    {
        return new DefaultProviders();
    }
}
}

namespace Illuminate\Support {
class AggregateServiceProvider extends ServiceProvider
{
    protected $providers = [];
    protected $instances = [];
    public function register()
    {
        $this->instances = [];
        foreach ($this->providers as $provider) {
            $this->instances[] = $this->app->register($provider);
        }
    }
    public function provides()
    {
        $provides = [];
        foreach ($this->providers as $provider) {
            $instance = $this->app->resolveProvider($provider);
            $provides = array_merge($provides, $instance->provides());
        }
        return $provides;
    }
}
}

namespace Illuminate\Support\Facades {
use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;
use Illuminate\Support\Js;
use Illuminate\Support\Number;
use Illuminate\Support\Str;
use Illuminate\Support\Testing\Fakes\Fake;
use Mockery;
use Mockery\LegacyMockInterface;
use RuntimeException;
abstract class Facade
{
    protected static $app;
    protected static $resolvedInstance;
    protected static $cached = true;
    public static function resolved(Closure $callback)
    {
        $accessor = static::getFacadeAccessor();
        if (static::$app->resolved($accessor) === true) {
            $callback(static::getFacadeRoot(), static::$app);
        }
        static::$app->afterResolving($accessor, function ($service, $app) use ($callback) {
            $callback($service, $app);
        });
    }
    public static function spy()
    {
        if (!static::isMock()) {
            $class = static::getMockableClass();
            return tap($class ? Mockery::spy($class) : Mockery::spy(), function ($spy) {
                static::swap($spy);
            });
        }
    }
    public static function partialMock()
    {
        $name = static::getFacadeAccessor();
        $mock = static::isMock() ? static::$resolvedInstance[$name] : static::createFreshMockInstance();
        return $mock->makePartial();
    }
    public static function shouldReceive()
    {
        $name = static::getFacadeAccessor();
        $mock = static::isMock() ? static::$resolvedInstance[$name] : static::createFreshMockInstance();
        return $mock->shouldReceive(...func_get_args());
    }
    public static function expects()
    {
        $name = static::getFacadeAccessor();
        $mock = static::isMock() ? static::$resolvedInstance[$name] : static::createFreshMockInstance();
        return $mock->expects(...func_get_args());
    }
    protected static function createFreshMockInstance()
    {
        return tap(static::createMock(), function ($mock) {
            static::swap($mock);
            $mock->shouldAllowMockingProtectedMethods();
        });
    }
    protected static function createMock()
    {
        $class = static::getMockableClass();
        return $class ? Mockery::mock($class) : Mockery::mock();
    }
    protected static function isMock()
    {
        $name = static::getFacadeAccessor();
        return isset(static::$resolvedInstance[$name]) && static::$resolvedInstance[$name] instanceof LegacyMockInterface;
    }
    protected static function getMockableClass()
    {
        if ($root = static::getFacadeRoot()) {
            return get_class($root);
        }
    }
    public static function swap($instance)
    {
        static::$resolvedInstance[static::getFacadeAccessor()] = $instance;
        if (isset(static::$app)) {
            static::$app->instance(static::getFacadeAccessor(), $instance);
        }
    }
    protected static function isFake()
    {
        $name = static::getFacadeAccessor();
        return isset(static::$resolvedInstance[$name]) && static::$resolvedInstance[$name] instanceof Fake;
    }
    public static function getFacadeRoot()
    {
        return static::resolveFacadeInstance(static::getFacadeAccessor());
    }
    protected static function getFacadeAccessor()
    {
        throw new RuntimeException('Facade does not implement getFacadeAccessor method.');
    }
    protected static function resolveFacadeInstance($name)
    {
        if (isset(static::$resolvedInstance[$name])) {
            return static::$resolvedInstance[$name];
        }
        if (static::$app) {
            if (static::$cached) {
                return static::$resolvedInstance[$name] = static::$app[$name];
            }
            return static::$app[$name];
        }
    }
    public static function clearResolvedInstance($name)
    {
        unset(static::$resolvedInstance[$name]);
    }
    public static function clearResolvedInstances()
    {
        static::$resolvedInstance = [];
    }
    public static function defaultAliases()
    {
        return collect(['App' => App::class, 'Arr' => Arr::class, 'Artisan' => Artisan::class, 'Auth' => Auth::class, 'Blade' => Blade::class, 'Broadcast' => Broadcast::class, 'Bus' => Bus::class, 'Cache' => Cache::class, 'Config' => Config::class, 'Cookie' => Cookie::class, 'Crypt' => Crypt::class, 'Date' => Date::class, 'DB' => DB::class, 'Eloquent' => Model::class, 'Event' => Event::class, 'File' => File::class, 'Gate' => Gate::class, 'Hash' => Hash::class, 'Http' => Http::class, 'Js' => Js::class, 'Lang' => Lang::class, 'Log' => Log::class, 'Mail' => Mail::class, 'Notification' => Notification::class, 'Number' => Number::class, 'Password' => Password::class, 'Process' => Process::class, 'Queue' => Queue::class, 'RateLimiter' => RateLimiter::class, 'Redirect' => Redirect::class, 'Request' => Request::class, 'Response' => Response::class, 'Route' => Route::class, 'Schema' => Schema::class, 'Session' => Session::class, 'Storage' => Storage::class, 'Str' => Str::class, 'URL' => URL::class, 'Validator' => Validator::class, 'View' => View::class, 'Vite' => Vite::class]);
    }
    public static function getFacadeApplication()
    {
        return static::$app;
    }
    public static function setFacadeApplication($app)
    {
        static::$app = $app;
    }
    public static function __callStatic($method, $args)
    {
        $instance = static::getFacadeRoot();
        if (!$instance) {
            throw new RuntimeException('A facade root has not been set.');
        }
        return $instance->{$method}(...$args);
    }
}
}

namespace Illuminate\Support {
use Closure;
use Illuminate\Support\Traits\Macroable;
use JsonException;
use League\CommonMark\Environment\Environment;
use League\CommonMark\Extension\GithubFlavoredMarkdownExtension;
use League\CommonMark\Extension\InlinesOnly\InlinesOnlyExtension;
use League\CommonMark\GithubFlavoredMarkdownConverter;
use League\CommonMark\MarkdownConverter;
use Ramsey\Uuid\Codec\TimestampFirstCombCodec;
use Ramsey\Uuid\Generator\CombGenerator;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidFactory;
use Symfony\Component\Uid\Ulid;
use Throwable;
use Traversable;
use voku\helper\ASCII;
class Str
{
    use Macroable;
    protected static $snakeCache = [];
    protected static $camelCache = [];
    protected static $studlyCache = [];
    protected static $uuidFactory;
    protected static $ulidFactory;
    protected static $randomStringFactory;
    public static function of($string)
    {
        return new Stringable($string);
    }
    public static function after($subject, $search)
    {
        return $search === '' ? $subject : array_reverse(explode($search, $subject, 2))[0];
    }
    public static function afterLast($subject, $search)
    {
        if ($search === '') {
            return $subject;
        }
        $position = strrpos($subject, (string) $search);
        if ($position === false) {
            return $subject;
        }
        return substr($subject, $position + strlen($search));
    }
    public static function ascii($value, $language = 'en')
    {
        return ASCII::to_ascii((string) $value, $language);
    }
    public static function transliterate($string, $unknown = '?', $strict = false)
    {
        return ASCII::to_transliterate($string, $unknown, $strict);
    }
    public static function before($subject, $search)
    {
        if ($search === '') {
            return $subject;
        }
        $result = strstr($subject, (string) $search, true);
        return $result === false ? $subject : $result;
    }
    public static function beforeLast($subject, $search)
    {
        if ($search === '') {
            return $subject;
        }
        $pos = mb_strrpos($subject, $search);
        if ($pos === false) {
            return $subject;
        }
        return static::substr($subject, 0, $pos);
    }
    public static function between($subject, $from, $to)
    {
        if ($from === '' || $to === '') {
            return $subject;
        }
        return static::beforeLast(static::after($subject, $from), $to);
    }
    public static function betweenFirst($subject, $from, $to)
    {
        if ($from === '' || $to === '') {
            return $subject;
        }
        return static::before(static::after($subject, $from), $to);
    }
    public static function camel($value)
    {
        if (isset(static::$camelCache[$value])) {
            return static::$camelCache[$value];
        }
        return static::$camelCache[$value] = lcfirst(static::studly($value));
    }
    public static function charAt($subject, $index)
    {
        $length = mb_strlen($subject);
        if ($index < 0 ? $index < -$length : $index > $length - 1) {
            return false;
        }
        return mb_substr($subject, $index, 1);
    }
    public static function contains($haystack, $needles, $ignoreCase = false)
    {
        if ($ignoreCase) {
            $haystack = mb_strtolower($haystack);
        }
        if (!is_iterable($needles)) {
            $needles = (array) $needles;
        }
        foreach ($needles as $needle) {
            if ($ignoreCase) {
                $needle = mb_strtolower($needle);
            }
            if ($needle !== '' && str_contains($haystack, $needle)) {
                return true;
            }
        }
        return false;
    }
    public static function containsAll($haystack, $needles, $ignoreCase = false)
    {
        foreach ($needles as $needle) {
            if (!static::contains($haystack, $needle, $ignoreCase)) {
                return false;
            }
        }
        return true;
    }
    public static function convertCase(string $string, int $mode = MB_CASE_FOLD, ?string $encoding = 'UTF-8')
    {
        return mb_convert_case($string, $mode, $encoding);
    }
    public static function endsWith($haystack, $needles)
    {
        if (!is_iterable($needles)) {
            $needles = (array) $needles;
        }
        foreach ($needles as $needle) {
            if ((string) $needle !== '' && str_ends_with($haystack, $needle)) {
                return true;
            }
        }
        return false;
    }
    public static function excerpt($text, $phrase = '', $options = [])
    {
        $radius = $options['radius'] ?? 100;
        $omission = $options['omission'] ?? '...';
        preg_match('/^(.*?)(' . preg_quote((string) $phrase, '/') . ')(.*)$/iu', (string) $text, $matches);
        if (empty($matches)) {
            return null;
        }
        $start = ltrim($matches[1]);
        $start = str(mb_substr($start, max(mb_strlen($start, 'UTF-8') - $radius, 0), $radius, 'UTF-8'))->ltrim()->unless(fn($startWithRadius) => $startWithRadius->exactly($start), fn($startWithRadius) => $startWithRadius->prepend($omission));
        $end = rtrim($matches[3]);
        $end = str(mb_substr($end, 0, $radius, 'UTF-8'))->rtrim()->unless(fn($endWithRadius) => $endWithRadius->exactly($end), fn($endWithRadius) => $endWithRadius->append($omission));
        return $start->append($matches[2], $end)->toString();
    }
    public static function finish($value, $cap)
    {
        $quoted = preg_quote($cap, '/');
        return preg_replace('/(?:' . $quoted . ')+$/u', '', $value) . $cap;
    }
    public static function wrap($value, $before, $after = null)
    {
        return $before . $value . $after ??= $before;
    }
    public static function unwrap($value, $before, $after = null)
    {
        if (static::startsWith($value, $before)) {
            $value = static::substr($value, static::length($before));
        }
        if (static::endsWith($value, $after ??= $before)) {
            $value = static::substr($value, 0, -static::length($after));
        }
        return $value;
    }
    public static function is($pattern, $value)
    {
        $value = (string) $value;
        if (!is_iterable($pattern)) {
            $pattern = [$pattern];
        }
        foreach ($pattern as $pattern) {
            $pattern = (string) $pattern;
            if ($pattern === $value) {
                return true;
            }
            $pattern = preg_quote($pattern, '#');
            $pattern = str_replace('\*', '.*', $pattern);
            if (preg_match('#^' . $pattern . '\z#u', $value) === 1) {
                return true;
            }
        }
        return false;
    }
    public static function isAscii($value)
    {
        return ASCII::is_ascii((string) $value);
    }
    public static function isJson($value)
    {
        if (!is_string($value)) {
            return false;
        }
        if (function_exists('json_validate')) {
            return json_validate($value, 512);
        }
        try {
            json_decode($value, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }
        return true;
    }
    public static function isUrl($value, array $protocols = [])
    {
        if (!is_string($value)) {
            return false;
        }
        $protocolList = empty($protocols) ? 'aaa|aaas|about|acap|acct|acd|acr|adiumxtra|adt|afp|afs|aim|amss|android|appdata|apt|ark|attachment|aw|barion|beshare|bitcoin|bitcoincash|blob|bolo|browserext|calculator|callto|cap|cast|casts|chrome|chrome-extension|cid|coap|coap\+tcp|coap\+ws|coaps|coaps\+tcp|coaps\+ws|com-eventbrite-attendee|content|conti|crid|cvs|dab|data|dav|diaspora|dict|did|dis|dlna-playcontainer|dlna-playsingle|dns|dntp|dpp|drm|drop|dtn|dvb|ed2k|elsi|example|facetime|fax|feed|feedready|file|filesystem|finger|first-run-pen-experience|fish|fm|ftp|fuchsia-pkg|geo|gg|git|gizmoproject|go|gopher|graph|gtalk|h323|ham|hcap|hcp|http|https|hxxp|hxxps|hydrazone|iax|icap|icon|im|imap|info|iotdisco|ipn|ipp|ipps|irc|irc6|ircs|iris|iris\.beep|iris\.lwz|iris\.xpc|iris\.xpcs|isostore|itms|jabber|jar|jms|keyparc|lastfm|ldap|ldaps|leaptofrogans|lorawan|lvlt|magnet|mailserver|mailto|maps|market|message|mid|mms|modem|mongodb|moz|ms-access|ms-browser-extension|ms-calculator|ms-drive-to|ms-enrollment|ms-excel|ms-eyecontrolspeech|ms-gamebarservices|ms-gamingoverlay|ms-getoffice|ms-help|ms-infopath|ms-inputapp|ms-lockscreencomponent-config|ms-media-stream-id|ms-mixedrealitycapture|ms-mobileplans|ms-officeapp|ms-people|ms-project|ms-powerpoint|ms-publisher|ms-restoretabcompanion|ms-screenclip|ms-screensketch|ms-search|ms-search-repair|ms-secondary-screen-controller|ms-secondary-screen-setup|ms-settings|ms-settings-airplanemode|ms-settings-bluetooth|ms-settings-camera|ms-settings-cellular|ms-settings-cloudstorage|ms-settings-connectabledevices|ms-settings-displays-topology|ms-settings-emailandaccounts|ms-settings-language|ms-settings-location|ms-settings-lock|ms-settings-nfctransactions|ms-settings-notifications|ms-settings-power|ms-settings-privacy|ms-settings-proximity|ms-settings-screenrotation|ms-settings-wifi|ms-settings-workplace|ms-spd|ms-sttoverlay|ms-transit-to|ms-useractivityset|ms-virtualtouchpad|ms-visio|ms-walk-to|ms-whiteboard|ms-whiteboard-cmd|ms-word|msnim|msrp|msrps|mss|mtqp|mumble|mupdate|mvn|news|nfs|ni|nih|nntp|notes|ocf|oid|onenote|onenote-cmd|opaquelocktoken|openpgp4fpr|pack|palm|paparazzi|payto|pkcs11|platform|pop|pres|prospero|proxy|pwid|psyc|pttp|qb|query|redis|rediss|reload|res|resource|rmi|rsync|rtmfp|rtmp|rtsp|rtsps|rtspu|s3|secondlife|service|session|sftp|sgn|shttp|sieve|simpleledger|sip|sips|skype|smb|sms|smtp|snews|snmp|soap\.beep|soap\.beeps|soldat|spiffe|spotify|ssh|steam|stun|stuns|submit|svn|tag|teamspeak|tel|teliaeid|telnet|tftp|tg|things|thismessage|tip|tn3270|tool|ts3server|turn|turns|tv|udp|unreal|urn|ut2004|v-event|vemmi|ventrilo|videotex|vnc|view-source|wais|webcal|wpid|ws|wss|wtai|wyciwyg|xcon|xcon-userid|xfire|xmlrpc\.beep|xmlrpc\.beeps|xmpp|xri|ymsgr|z39\.50|z39\.50r|z39\.50s' : implode('|', $protocols);
        $pattern = '~^
            (LARAVEL_PROTOCOLS)://                                 # protocol
            (((?:[\_\.\pL\pN-]|%[0-9A-Fa-f]{2})+:)?((?:[\_\.\pL\pN-]|%[0-9A-Fa-f]{2})+)@)?  # basic auth
            (
                ([\pL\pN\pS\-\_\.])+(\.?([\pL\pN]|xn\-\-[\pL\pN-]+)+\.?) # a domain name
                    |                                                 # or
                \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}                    # an IP address
                    |                                                 # or
                \[
                    (?:(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-f]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-f]{1,4})))?::(?:(?:(?:[0-9a-f]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,1}(?:(?:[0-9a-f]{1,4})))?::(?:(?:(?:[0-9a-f]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,2}(?:(?:[0-9a-f]{1,4})))?::(?:(?:(?:[0-9a-f]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,3}(?:(?:[0-9a-f]{1,4})))?::(?:(?:[0-9a-f]{1,4})):)(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,4}(?:(?:[0-9a-f]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,5}(?:(?:[0-9a-f]{1,4})))?::)(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,6}(?:(?:[0-9a-f]{1,4})))?::))))
                \]  # an IPv6 address
            )
            (:[0-9]+)?                              # a port (optional)
            (?:/ (?:[\pL\pN\-._\~!$&\'()*+,;=:@]|%[0-9A-Fa-f]{2})* )*          # a path
            (?:\? (?:[\pL\pN\-._\~!$&\'\[\]()*+,;=:@/?]|%[0-9A-Fa-f]{2})* )?   # a query (optional)
            (?:\# (?:[\pL\pN\-._\~!$&\'()*+,;=:@/?]|%[0-9A-Fa-f]{2})* )?       # a fragment (optional)
        $~ixu';
        return preg_match(str_replace('LARAVEL_PROTOCOLS', $protocolList, $pattern), $value) > 0;
    }
    public static function isUuid($value)
    {
        if (!is_string($value)) {
            return false;
        }
        return preg_match('/^[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$/D', $value) > 0;
    }
    public static function isUlid($value)
    {
        if (!is_string($value)) {
            return false;
        }
        return Ulid::isValid($value);
    }
    public static function kebab($value)
    {
        return static::snake($value, '-');
    }
    public static function length($value, $encoding = null)
    {
        return mb_strlen($value, $encoding);
    }
    public static function limit($value, $limit = 100, $end = '...')
    {
        if (mb_strwidth($value, 'UTF-8') <= $limit) {
            return $value;
        }
        return rtrim(mb_strimwidth($value, 0, $limit, '', 'UTF-8')) . $end;
    }
    public static function lower($value)
    {
        return mb_strtolower($value, 'UTF-8');
    }
    public static function words($value, $words = 100, $end = '...')
    {
        preg_match('/^\s*+(?:\S++\s*+){1,' . $words . '}/u', $value, $matches);
        if (!isset($matches[0]) || static::length($value) === static::length($matches[0])) {
            return $value;
        }
        return rtrim($matches[0]) . $end;
    }
    public static function markdown($string, array $options = [])
    {
        $converter = new GithubFlavoredMarkdownConverter($options);
        return (string) $converter->convert($string);
    }
    public static function inlineMarkdown($string, array $options = [])
    {
        $environment = new Environment($options);
        $environment->addExtension(new GithubFlavoredMarkdownExtension());
        $environment->addExtension(new InlinesOnlyExtension());
        $converter = new MarkdownConverter($environment);
        return (string) $converter->convert($string);
    }
    public static function mask($string, $character, $index, $length = null, $encoding = 'UTF-8')
    {
        if ($character === '') {
            return $string;
        }
        $segment = mb_substr($string, $index, $length, $encoding);
        if ($segment === '') {
            return $string;
        }
        $strlen = mb_strlen($string, $encoding);
        $startIndex = $index;
        if ($index < 0) {
            $startIndex = $index < -$strlen ? 0 : $strlen + $index;
        }
        $start = mb_substr($string, 0, $startIndex, $encoding);
        $segmentLen = mb_strlen($segment, $encoding);
        $end = mb_substr($string, $startIndex + $segmentLen);
        return $start . str_repeat(mb_substr($character, 0, 1, $encoding), $segmentLen) . $end;
    }
    public static function match($pattern, $subject)
    {
        preg_match($pattern, $subject, $matches);
        if (!$matches) {
            return '';
        }
        return $matches[1] ?? $matches[0];
    }
    public static function isMatch($pattern, $value)
    {
        $value = (string) $value;
        if (!is_iterable($pattern)) {
            $pattern = [$pattern];
        }
        foreach ($pattern as $pattern) {
            $pattern = (string) $pattern;
            if (preg_match($pattern, $value) === 1) {
                return true;
            }
        }
        return false;
    }
    public static function matchAll($pattern, $subject)
    {
        preg_match_all($pattern, $subject, $matches);
        if (empty($matches[0])) {
            return collect();
        }
        return collect($matches[1] ?? $matches[0]);
    }
    public static function padBoth($value, $length, $pad = ' ')
    {
        if (function_exists('mb_str_pad')) {
            return mb_str_pad($value, $length, $pad, STR_PAD_BOTH);
        }
        $short = max(0, $length - mb_strlen($value));
        $shortLeft = floor($short / 2);
        $shortRight = ceil($short / 2);
        return mb_substr(str_repeat($pad, $shortLeft), 0, $shortLeft) . $value . mb_substr(str_repeat($pad, $shortRight), 0, $shortRight);
    }
    public static function padLeft($value, $length, $pad = ' ')
    {
        if (function_exists('mb_str_pad')) {
            return mb_str_pad($value, $length, $pad, STR_PAD_LEFT);
        }
        $short = max(0, $length - mb_strlen($value));
        return mb_substr(str_repeat($pad, $short), 0, $short) . $value;
    }
    public static function padRight($value, $length, $pad = ' ')
    {
        if (function_exists('mb_str_pad')) {
            return mb_str_pad($value, $length, $pad, STR_PAD_RIGHT);
        }
        $short = max(0, $length - mb_strlen($value));
        return $value . mb_substr(str_repeat($pad, $short), 0, $short);
    }
    public static function parseCallback($callback, $default = null)
    {
        if (static::contains($callback, "@anonymous\x00")) {
            if (static::substrCount($callback, '@') > 1) {
                return [static::beforeLast($callback, '@'), static::afterLast($callback, '@')];
            }
            return [$callback, $default];
        }
        return static::contains($callback, '@') ? explode('@', $callback, 2) : [$callback, $default];
    }
    public static function plural($value, $count = 2)
    {
        return Pluralizer::plural($value, $count);
    }
    public static function pluralStudly($value, $count = 2)
    {
        $parts = preg_split('/(.)(?=[A-Z])/u', $value, -1, PREG_SPLIT_DELIM_CAPTURE);
        $lastWord = array_pop($parts);
        return implode('', $parts) . self::plural($lastWord, $count);
    }
    public static function password($length = 32, $letters = true, $numbers = true, $symbols = true, $spaces = false)
    {
        $password = new Collection();
        $options = (new Collection(['letters' => $letters === true ? ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'] : null, 'numbers' => $numbers === true ? ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'] : null, 'symbols' => $symbols === true ? ['~', '!', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '.', ',', '<', '>', '?', '/', '\\', '{', '}', '[', ']', '|', ':', ';'] : null, 'spaces' => $spaces === true ? [' '] : null]))->filter()->each(fn($c) => $password->push($c[random_int(0, count($c) - 1)]))->flatten();
        $length = $length - $password->count();
        return $password->merge($options->pipe(fn($c) => Collection::times($length, fn() => $c[random_int(0, $c->count() - 1)])))->shuffle()->implode('');
    }
    public static function position($haystack, $needle, $offset = 0, $encoding = null)
    {
        return mb_strpos($haystack, (string) $needle, $offset, $encoding);
    }
    public static function random($length = 16)
    {
        return (static::$randomStringFactory ?? function ($length) {
            $string = '';
            while (($len = strlen($string)) < $length) {
                $size = $length - $len;
                $bytesSize = (int) ceil($size / 3) * 3;
                $bytes = random_bytes($bytesSize);
                $string .= substr(str_replace(['/', '+', '='], '', base64_encode($bytes)), 0, $size);
            }
            return $string;
        })($length);
    }
    public static function createRandomStringsUsing(?callable $factory = null)
    {
        static::$randomStringFactory = $factory;
    }
    public static function createRandomStringsUsingSequence(array $sequence, $whenMissing = null)
    {
        $next = 0;
        $whenMissing ??= function ($length) use (&$next) {
            $factoryCache = static::$randomStringFactory;
            static::$randomStringFactory = null;
            $randomString = static::random($length);
            static::$randomStringFactory = $factoryCache;
            $next++;
            return $randomString;
        };
        static::createRandomStringsUsing(function ($length) use (&$next, $sequence, $whenMissing) {
            if (array_key_exists($next, $sequence)) {
                return $sequence[$next++];
            }
            return $whenMissing($length);
        });
    }
    public static function createRandomStringsNormally()
    {
        static::$randomStringFactory = null;
    }
    public static function repeat(string $string, int $times)
    {
        return str_repeat($string, $times);
    }
    public static function replaceArray($search, $replace, $subject)
    {
        if ($replace instanceof Traversable) {
            $replace = collect($replace)->all();
        }
        $segments = explode($search, $subject);
        $result = array_shift($segments);
        foreach ($segments as $segment) {
            $result .= self::toStringOr(array_shift($replace) ?? $search, $search) . $segment;
        }
        return $result;
    }
    private static function toStringOr($value, $fallback)
    {
        try {
            return (string) $value;
        } catch (Throwable $e) {
            return $fallback;
        }
    }
    public static function replace($search, $replace, $subject, $caseSensitive = true)
    {
        if ($search instanceof Traversable) {
            $search = collect($search)->all();
        }
        if ($replace instanceof Traversable) {
            $replace = collect($replace)->all();
        }
        if ($subject instanceof Traversable) {
            $subject = collect($subject)->all();
        }
        return $caseSensitive ? str_replace($search, $replace, $subject) : str_ireplace($search, $replace, $subject);
    }
    public static function replaceFirst($search, $replace, $subject)
    {
        $search = (string) $search;
        if ($search === '') {
            return $subject;
        }
        $position = strpos($subject, $search);
        if ($position !== false) {
            return substr_replace($subject, $replace, $position, strlen($search));
        }
        return $subject;
    }
    public static function replaceStart($search, $replace, $subject)
    {
        $search = (string) $search;
        if ($search === '') {
            return $subject;
        }
        if (static::startsWith($subject, $search)) {
            return static::replaceFirst($search, $replace, $subject);
        }
        return $subject;
    }
    public static function replaceLast($search, $replace, $subject)
    {
        $search = (string) $search;
        if ($search === '') {
            return $subject;
        }
        $position = strrpos($subject, $search);
        if ($position !== false) {
            return substr_replace($subject, $replace, $position, strlen($search));
        }
        return $subject;
    }
    public static function replaceEnd($search, $replace, $subject)
    {
        $search = (string) $search;
        if ($search === '') {
            return $subject;
        }
        if (static::endsWith($subject, $search)) {
            return static::replaceLast($search, $replace, $subject);
        }
        return $subject;
    }
    public static function replaceMatches($pattern, $replace, $subject, $limit = -1)
    {
        if ($replace instanceof Closure) {
            return preg_replace_callback($pattern, $replace, $subject, $limit);
        }
        return preg_replace($pattern, $replace, $subject, $limit);
    }
    public static function remove($search, $subject, $caseSensitive = true)
    {
        if ($search instanceof Traversable) {
            $search = collect($search)->all();
        }
        return $caseSensitive ? str_replace($search, '', $subject) : str_ireplace($search, '', $subject);
    }
    public static function reverse(string $value)
    {
        return implode(array_reverse(mb_str_split($value)));
    }
    public static function start($value, $prefix)
    {
        $quoted = preg_quote($prefix, '/');
        return $prefix . preg_replace('/^(?:' . $quoted . ')+/u', '', $value);
    }
    public static function upper($value)
    {
        return mb_strtoupper($value, 'UTF-8');
    }
    public static function title($value)
    {
        return mb_convert_case($value, MB_CASE_TITLE, 'UTF-8');
    }
    public static function headline($value)
    {
        $parts = explode(' ', $value);
        $parts = count($parts) > 1 ? array_map([static::class, 'title'], $parts) : array_map([static::class, 'title'], static::ucsplit(implode('_', $parts)));
        $collapsed = static::replace(['-', '_', ' '], '_', implode('_', $parts));
        return implode(' ', array_filter(explode('_', $collapsed)));
    }
    public static function apa($value)
    {
        if (trim($value) === '') {
            return $value;
        }
        $minorWords = ['and', 'as', 'but', 'for', 'if', 'nor', 'or', 'so', 'yet', 'a', 'an', 'the', 'at', 'by', 'for', 'in', 'of', 'off', 'on', 'per', 'to', 'up', 'via', 'et', 'ou', 'un', 'une', 'la', 'le', 'les', 'de', 'du', 'des', 'par', 'à'];
        $endPunctuation = ['.', '!', '?', ':', '—', ','];
        $words = preg_split('/\s+/', $value, -1, PREG_SPLIT_NO_EMPTY);
        for ($i = 0; $i < count($words); $i++) {
            $lowercaseWord = mb_strtolower($words[$i]);
            if (str_contains($lowercaseWord, '-')) {
                $hyphenatedWords = explode('-', $lowercaseWord);
                $hyphenatedWords = array_map(function ($part) use ($minorWords) {
                    return in_array($part, $minorWords) && mb_strlen($part) <= 3 ? $part : mb_strtoupper(mb_substr($part, 0, 1)) . mb_substr($part, 1);
                }, $hyphenatedWords);
                $words[$i] = implode('-', $hyphenatedWords);
            } else if (in_array($lowercaseWord, $minorWords) && mb_strlen($lowercaseWord) <= 3 && !($i === 0 || in_array(mb_substr($words[$i - 1], -1), $endPunctuation))) {
                $words[$i] = $lowercaseWord;
            } else {
                $words[$i] = mb_strtoupper(mb_substr($lowercaseWord, 0, 1)) . mb_substr($lowercaseWord, 1);
            }
        }
        return implode(' ', $words);
    }
    public static function singular($value)
    {
        return Pluralizer::singular($value);
    }
    public static function slug($title, $separator = '-', $language = 'en', $dictionary = ['@' => 'at'])
    {
        $title = $language ? static::ascii($title, $language) : $title;
        $flip = $separator === '-' ? '_' : '-';
        $title = preg_replace('![' . preg_quote($flip) . ']+!u', $separator, $title);
        foreach ($dictionary as $key => $value) {
            $dictionary[$key] = $separator . $value . $separator;
        }
        $title = str_replace(array_keys($dictionary), array_values($dictionary), $title);
        $title = preg_replace('![^' . preg_quote($separator) . '\pL\pN\s]+!u', '', static::lower($title));
        $title = preg_replace('![' . preg_quote($separator) . '\s]+!u', $separator, $title);
        return trim($title, $separator);
    }
    public static function snake($value, $delimiter = '_')
    {
        $key = $value;
        if (isset(static::$snakeCache[$key][$delimiter])) {
            return static::$snakeCache[$key][$delimiter];
        }
        if (!ctype_lower($value)) {
            $value = preg_replace('/\s+/u', '', ucwords($value));
            $value = static::lower(preg_replace('/(.)(?=[A-Z])/u', '$1' . $delimiter, $value));
        }
        return static::$snakeCache[$key][$delimiter] = $value;
    }
    public static function squish($value)
    {
        return preg_replace('~(\s|\x{3164}|\x{1160})+~u', ' ', preg_replace('~^[\s\x{FEFF}]+|[\s\x{FEFF}]+$~u', '', $value));
    }
    public static function startsWith($haystack, $needles)
    {
        if (!is_iterable($needles)) {
            $needles = [$needles];
        }
        foreach ($needles as $needle) {
            if ((string) $needle !== '' && str_starts_with($haystack, $needle)) {
                return true;
            }
        }
        return false;
    }
    public static function studly($value)
    {
        $key = $value;
        if (isset(static::$studlyCache[$key])) {
            return static::$studlyCache[$key];
        }
        $words = explode(' ', static::replace(['-', '_'], ' ', $value));
        $studlyWords = array_map(fn($word) => static::ucfirst($word), $words);
        return static::$studlyCache[$key] = implode($studlyWords);
    }
    public static function substr($string, $start, $length = null, $encoding = 'UTF-8')
    {
        return mb_substr($string, $start, $length, $encoding);
    }
    public static function substrCount($haystack, $needle, $offset = 0, $length = null)
    {
        if (!is_null($length)) {
            return substr_count($haystack, $needle, $offset, $length);
        }
        return substr_count($haystack, $needle, $offset);
    }
    public static function substrReplace($string, $replace, $offset = 0, $length = null)
    {
        if ($length === null) {
            $length = strlen($string);
        }
        return substr_replace($string, $replace, $offset, $length);
    }
    public static function swap(array $map, $subject)
    {
        return strtr($subject, $map);
    }
    public static function take($string, int $limit): string
    {
        if ($limit < 0) {
            return static::substr($string, $limit);
        }
        return static::substr($string, 0, $limit);
    }
    public static function toBase64($string): string
    {
        return base64_encode($string);
    }
    public static function fromBase64($string, $strict = false)
    {
        return base64_decode($string, $strict);
    }
    public static function lcfirst($string)
    {
        return static::lower(static::substr($string, 0, 1)) . static::substr($string, 1);
    }
    public static function ucfirst($string)
    {
        return static::upper(static::substr($string, 0, 1)) . static::substr($string, 1);
    }
    public static function ucsplit($string)
    {
        return preg_split('/(?=\p{Lu})/u', $string, -1, PREG_SPLIT_NO_EMPTY);
    }
    public static function wordCount($string, $characters = null)
    {
        return str_word_count($string, 0, $characters);
    }
    public static function wordWrap($string, $characters = 75, $break = "\n", $cutLongWords = false)
    {
        return wordwrap($string, $characters, $break, $cutLongWords);
    }
    public static function uuid()
    {
        return static::$uuidFactory ? call_user_func(static::$uuidFactory) : Uuid::uuid4();
    }
    public static function orderedUuid()
    {
        if (static::$uuidFactory) {
            return call_user_func(static::$uuidFactory);
        }
        $factory = new UuidFactory();
        $factory->setRandomGenerator(new CombGenerator($factory->getRandomGenerator(), $factory->getNumberConverter()));
        $factory->setCodec(new TimestampFirstCombCodec($factory->getUuidBuilder()));
        return $factory->uuid4();
    }
    public static function createUuidsUsing(?callable $factory = null)
    {
        static::$uuidFactory = $factory;
    }
    public static function createUuidsUsingSequence(array $sequence, $whenMissing = null)
    {
        $next = 0;
        $whenMissing ??= function () use (&$next) {
            $factoryCache = static::$uuidFactory;
            static::$uuidFactory = null;
            $uuid = static::uuid();
            static::$uuidFactory = $factoryCache;
            $next++;
            return $uuid;
        };
        static::createUuidsUsing(function () use (&$next, $sequence, $whenMissing) {
            if (array_key_exists($next, $sequence)) {
                return $sequence[$next++];
            }
            return $whenMissing();
        });
    }
    public static function freezeUuids(?Closure $callback = null)
    {
        $uuid = Str::uuid();
        Str::createUuidsUsing(fn() => $uuid);
        if ($callback !== null) {
            try {
                $callback($uuid);
            } finally {
                Str::createUuidsNormally();
            }
        }
        return $uuid;
    }
    public static function createUuidsNormally()
    {
        static::$uuidFactory = null;
    }
    public static function ulid($time = null)
    {
        if (static::$ulidFactory) {
            return call_user_func(static::$ulidFactory);
        }
        if ($time === null) {
            return new Ulid();
        }
        return new Ulid(Ulid::generate($time));
    }
    public static function createUlidsNormally()
    {
        static::$ulidFactory = null;
    }
    public static function createUlidsUsing(?callable $factory = null)
    {
        static::$ulidFactory = $factory;
    }
    public static function createUlidsUsingSequence(array $sequence, $whenMissing = null)
    {
        $next = 0;
        $whenMissing ??= function () use (&$next) {
            $factoryCache = static::$ulidFactory;
            static::$ulidFactory = null;
            $ulid = static::ulid();
            static::$ulidFactory = $factoryCache;
            $next++;
            return $ulid;
        };
        static::createUlidsUsing(function () use (&$next, $sequence, $whenMissing) {
            if (array_key_exists($next, $sequence)) {
                return $sequence[$next++];
            }
            return $whenMissing();
        });
    }
    public static function freezeUlids(?Closure $callback = null)
    {
        $ulid = Str::ulid();
        Str::createUlidsUsing(fn() => $ulid);
        if ($callback !== null) {
            try {
                $callback($ulid);
            } finally {
                Str::createUlidsNormally();
            }
        }
        return $ulid;
    }
    public static function flushCache()
    {
        static::$snakeCache = [];
        static::$camelCache = [];
        static::$studlyCache = [];
    }
}
}

namespace Illuminate\Support {
class NamespacedItemResolver
{
    protected $parsed = [];
    public function parseKey($key)
    {
        if (isset($this->parsed[$key])) {
            return $this->parsed[$key];
        }
        if (!str_contains($key, '::')) {
            $segments = explode('.', $key);
            $parsed = $this->parseBasicSegments($segments);
        } else {
            $parsed = $this->parseNamespacedSegments($key);
        }
        return $this->parsed[$key] = $parsed;
    }
    protected function parseBasicSegments(array $segments)
    {
        $group = $segments[0];
        $item = count($segments) === 1 ? null : implode('.', array_slice($segments, 1));
        return [null, $group, $item];
    }
    protected function parseNamespacedSegments($key)
    {
        [$namespace, $item] = explode('::', $key);
        $itemSegments = explode('.', $item);
        $groupAndItem = array_slice($this->parseBasicSegments($itemSegments), 1);
        return array_merge([$namespace], $groupAndItem);
    }
    public function setParsedKey($key, $parsed)
    {
        $this->parsed[$key] = $parsed;
    }
    public function flushParsedKeys()
    {
        $this->parsed = [];
    }
}
}

namespace Illuminate\Support\Facades {
class App extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'app';
    }
}
}

namespace Illuminate\Support\Facades {
class Route extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'router';
    }
}
}

namespace Illuminate\Support {
use Countable;
use Illuminate\Contracts\Support\MessageBag as MessageBagContract;
class ViewErrorBag implements Countable
{
    protected $bags = [];
    public function hasBag($key = 'default')
    {
        return isset($this->bags[$key]);
    }
    public function getBag($key)
    {
        return Arr::get($this->bags, $key) ?: new MessageBag();
    }
    public function getBags()
    {
        return $this->bags;
    }
    public function put($key, MessageBagContract $bag)
    {
        $this->bags[$key] = $bag;
        return $this;
    }
    public function any()
    {
        return $this->count() > 0;
    }
    public function count(): int
    {
        return $this->getBag('default')->count();
    }
    public function __call($method, $parameters)
    {
        return $this->getBag('default')->{$method}(...$parameters);
    }
    public function __get($key)
    {
        return $this->getBag($key);
    }
    public function __set($key, $value)
    {
        $this->put($key, $value);
    }
    public function __toString()
    {
        return (string) $this->getBag('default');
    }
}
}

namespace Illuminate\Support {
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\MessageBag as MessageBagContract;
use Illuminate\Contracts\Support\MessageProvider;
use JsonSerializable;
class MessageBag implements Jsonable, JsonSerializable, MessageBagContract, MessageProvider
{
    protected $messages = [];
    protected $format = ':message';
    public function __construct(array $messages = [])
    {
        foreach ($messages as $key => $value) {
            $value = $value instanceof Arrayable ? $value->toArray() : (array) $value;
            $this->messages[$key] = array_unique($value);
        }
    }
    public function keys()
    {
        return array_keys($this->messages);
    }
    public function add($key, $message)
    {
        if ($this->isUnique($key, $message)) {
            $this->messages[$key][] = $message;
        }
        return $this;
    }
    public function addIf($boolean, $key, $message)
    {
        return $boolean ? $this->add($key, $message) : $this;
    }
    protected function isUnique($key, $message)
    {
        $messages = (array) $this->messages;
        return !isset($messages[$key]) || !in_array($message, $messages[$key]);
    }
    public function merge($messages)
    {
        if ($messages instanceof MessageProvider) {
            $messages = $messages->getMessageBag()->getMessages();
        }
        $this->messages = array_merge_recursive($this->messages, $messages);
        return $this;
    }
    public function has($key)
    {
        if ($this->isEmpty()) {
            return false;
        }
        if (is_null($key)) {
            return $this->any();
        }
        $keys = is_array($key) ? $key : func_get_args();
        foreach ($keys as $key) {
            if ($this->first($key) === '') {
                return false;
            }
        }
        return true;
    }
    public function hasAny($keys = [])
    {
        if ($this->isEmpty()) {
            return false;
        }
        $keys = is_array($keys) ? $keys : func_get_args();
        foreach ($keys as $key) {
            if ($this->has($key)) {
                return true;
            }
        }
        return false;
    }
    public function missing($key)
    {
        $keys = is_array($key) ? $key : func_get_args();
        return !$this->hasAny($keys);
    }
    public function first($key = null, $format = null)
    {
        $messages = is_null($key) ? $this->all($format) : $this->get($key, $format);
        $firstMessage = Arr::first($messages, null, '');
        return is_array($firstMessage) ? Arr::first($firstMessage) : $firstMessage;
    }
    public function get($key, $format = null)
    {
        if (array_key_exists($key, $this->messages)) {
            return $this->transform($this->messages[$key], $this->checkFormat($format), $key);
        }
        if (str_contains($key, '*')) {
            return $this->getMessagesForWildcardKey($key, $format);
        }
        return [];
    }
    protected function getMessagesForWildcardKey($key, $format)
    {
        return collect($this->messages)->filter(function ($messages, $messageKey) use ($key) {
            return Str::is($key, $messageKey);
        })->map(function ($messages, $messageKey) use ($format) {
            return $this->transform($messages, $this->checkFormat($format), $messageKey);
        })->all();
    }
    public function all($format = null)
    {
        $format = $this->checkFormat($format);
        $all = [];
        foreach ($this->messages as $key => $messages) {
            $all = array_merge($all, $this->transform($messages, $format, $key));
        }
        return $all;
    }
    public function unique($format = null)
    {
        return array_unique($this->all($format));
    }
    public function forget($key)
    {
        unset($this->messages[$key]);
        return $this;
    }
    protected function transform($messages, $format, $messageKey)
    {
        if ($format == ':message') {
            return (array) $messages;
        }
        return collect((array) $messages)->map(function ($message) use ($format, $messageKey) {
            return str_replace([':message', ':key'], [$message, $messageKey], $format);
        })->all();
    }
    protected function checkFormat($format)
    {
        return $format ?: $this->format;
    }
    public function messages()
    {
        return $this->messages;
    }
    public function getMessages()
    {
        return $this->messages();
    }
    public function getMessageBag()
    {
        return $this;
    }
    public function getFormat()
    {
        return $this->format;
    }
    public function setFormat($format = ':message')
    {
        $this->format = $format;
        return $this;
    }
    public function isEmpty()
    {
        return !$this->any();
    }
    public function isNotEmpty()
    {
        return $this->any();
    }
    public function any()
    {
        return $this->count() > 0;
    }
    public function count(): int
    {
        return count($this->messages, COUNT_RECURSIVE) - count($this->messages);
    }
    public function toArray()
    {
        return $this->getMessages();
    }
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
    public function toJson($options = 0)
    {
        return json_encode($this->jsonSerialize(), $options);
    }
    public function __toString()
    {
        return $this->toJson();
    }
}
}

namespace Illuminate\Support\Facades {
class View extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'view';
    }
}
}

namespace Illuminate\Support {
use Closure;
use Illuminate\Contracts\Container\Container;
use InvalidArgumentException;
abstract class Manager
{
    protected $container;
    protected $config;
    protected $customCreators = [];
    protected $drivers = [];
    public function __construct(Container $container)
    {
        $this->container = $container;
        $this->config = $container->make('config');
    }
    abstract public function getDefaultDriver();
    public function driver($driver = null)
    {
        $driver = $driver ?: $this->getDefaultDriver();
        if (is_null($driver)) {
            throw new InvalidArgumentException(sprintf('Unable to resolve NULL driver for [%s].', static::class));
        }
        if (!isset($this->drivers[$driver])) {
            $this->drivers[$driver] = $this->createDriver($driver);
        }
        return $this->drivers[$driver];
    }
    protected function createDriver($driver)
    {
        if (isset($this->customCreators[$driver])) {
            return $this->callCustomCreator($driver);
        }
        $method = 'create' . Str::studly($driver) . 'Driver';
        if (method_exists($this, $method)) {
            return $this->{$method}();
        }
        throw new InvalidArgumentException("Driver [{$driver}] not supported.");
    }
    protected function callCustomCreator($driver)
    {
        return $this->customCreators[$driver]($this->container);
    }
    public function extend($driver, Closure $callback)
    {
        $this->customCreators[$driver] = $callback;
        return $this;
    }
    public function getDrivers()
    {
        return $this->drivers;
    }
    public function getContainer()
    {
        return $this->container;
    }
    public function setContainer(Container $container)
    {
        $this->container = $container;
        return $this;
    }
    public function forgetDrivers()
    {
        $this->drivers = [];
        return $this;
    }
    public function __call($method, $parameters)
    {
        return $this->driver()->{$method}(...$parameters);
    }
}
}

namespace Illuminate\Support\Facades {
class Log extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'log';
    }
}
}

namespace Illuminate\Events {
use Closure;
use Exception;
use Illuminate\Container\Container;
use Illuminate\Contracts\Broadcasting\Factory as BroadcastFactory;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Contracts\Container\Container as ContainerContract;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;
use Illuminate\Contracts\Events\ShouldHandleEventsAfterCommit;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Contracts\Queue\ShouldQueueAfterCommit;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Support\Traits\Macroable;
use Illuminate\Support\Traits\ReflectsClosures;
use ReflectionClass;
class Dispatcher implements DispatcherContract
{
    use Macroable, ReflectsClosures;
    protected $container;
    protected $listeners = [];
    protected $wildcards = [];
    protected $wildcardsCache = [];
    protected $queueResolver;
    protected $transactionManagerResolver;
    public function __construct(?ContainerContract $container = null)
    {
        $this->container = $container ?: new Container();
    }
    public function listen($events, $listener = null)
    {
        if ($events instanceof Closure) {
            return collect($this->firstClosureParameterTypes($events))->each(function ($event) use ($events) {
                $this->listen($event, $events);
            });
        } elseif ($events instanceof QueuedClosure) {
            return collect($this->firstClosureParameterTypes($events->closure))->each(function ($event) use ($events) {
                $this->listen($event, $events->resolve());
            });
        } elseif ($listener instanceof QueuedClosure) {
            $listener = $listener->resolve();
        }
        foreach ((array) $events as $event) {
            if (str_contains($event, '*')) {
                $this->setupWildcardListen($event, $listener);
            } else {
                $this->listeners[$event][] = $listener;
            }
        }
    }
    protected function setupWildcardListen($event, $listener)
    {
        $this->wildcards[$event][] = $listener;
        $this->wildcardsCache = [];
    }
    public function hasListeners($eventName)
    {
        return isset($this->listeners[$eventName]) || isset($this->wildcards[$eventName]) || $this->hasWildcardListeners($eventName);
    }
    public function hasWildcardListeners($eventName)
    {
        foreach ($this->wildcards as $key => $listeners) {
            if (Str::is($key, $eventName)) {
                return true;
            }
        }
        return false;
    }
    public function push($event, $payload = [])
    {
        $this->listen($event . '_pushed', function () use ($event, $payload) {
            $this->dispatch($event, $payload);
        });
    }
    public function flush($event)
    {
        $this->dispatch($event . '_pushed');
    }
    public function subscribe($subscriber)
    {
        $subscriber = $this->resolveSubscriber($subscriber);
        $events = $subscriber->subscribe($this);
        if (is_array($events)) {
            foreach ($events as $event => $listeners) {
                foreach (Arr::wrap($listeners) as $listener) {
                    if (is_string($listener) && method_exists($subscriber, $listener)) {
                        $this->listen($event, [get_class($subscriber), $listener]);
                        continue;
                    }
                    $this->listen($event, $listener);
                }
            }
        }
    }
    protected function resolveSubscriber($subscriber)
    {
        if (is_string($subscriber)) {
            return $this->container->make($subscriber);
        }
        return $subscriber;
    }
    public function until($event, $payload = [])
    {
        return $this->dispatch($event, $payload, true);
    }
    public function dispatch($event, $payload = [], $halt = false)
    {
        [$isEventObject, $event, $payload] = [is_object($event), ...$this->parseEventAndPayload($event, $payload)];
        if ($isEventObject && $payload[0] instanceof ShouldDispatchAfterCommit && !is_null($transactions = $this->resolveTransactionManager())) {
            $transactions->addCallback(fn() => $this->invokeListeners($event, $payload, $halt));
            return null;
        }
        return $this->invokeListeners($event, $payload, $halt);
    }
    protected function invokeListeners($event, $payload, $halt = false)
    {
        if ($this->shouldBroadcast($payload)) {
            $this->broadcastEvent($payload[0]);
        }
        $responses = [];
        foreach ($this->getListeners($event) as $listener) {
            $response = $listener($event, $payload);
            if ($halt && !is_null($response)) {
                return $response;
            }
            if ($response === false) {
                break;
            }
            $responses[] = $response;
        }
        return $halt ? null : $responses;
    }
    protected function parseEventAndPayload($event, $payload)
    {
        if (is_object($event)) {
            [$payload, $event] = [[$event], get_class($event)];
        }
        return [$event, Arr::wrap($payload)];
    }
    protected function shouldBroadcast(array $payload)
    {
        return isset($payload[0]) && $payload[0] instanceof ShouldBroadcast && $this->broadcastWhen($payload[0]);
    }
    protected function broadcastWhen($event)
    {
        return method_exists($event, 'broadcastWhen') ? $event->broadcastWhen() : true;
    }
    protected function broadcastEvent($event)
    {
        $this->container->make(BroadcastFactory::class)->queue($event);
    }
    public function getListeners($eventName)
    {
        $listeners = array_merge($this->prepareListeners($eventName), $this->wildcardsCache[$eventName] ?? $this->getWildcardListeners($eventName));
        return class_exists($eventName, false) ? $this->addInterfaceListeners($eventName, $listeners) : $listeners;
    }
    protected function getWildcardListeners($eventName)
    {
        $wildcards = [];
        foreach ($this->wildcards as $key => $listeners) {
            if (Str::is($key, $eventName)) {
                foreach ($listeners as $listener) {
                    $wildcards[] = $this->makeListener($listener, true);
                }
            }
        }
        return $this->wildcardsCache[$eventName] = $wildcards;
    }
    protected function addInterfaceListeners($eventName, array $listeners = [])
    {
        foreach (class_implements($eventName) as $interface) {
            if (isset($this->listeners[$interface])) {
                foreach ($this->prepareListeners($interface) as $names) {
                    $listeners = array_merge($listeners, (array) $names);
                }
            }
        }
        return $listeners;
    }
    protected function prepareListeners(string $eventName)
    {
        $listeners = [];
        foreach ($this->listeners[$eventName] ?? [] as $listener) {
            $listeners[] = $this->makeListener($listener);
        }
        return $listeners;
    }
    public function makeListener($listener, $wildcard = false)
    {
        if (is_string($listener)) {
            return $this->createClassListener($listener, $wildcard);
        }
        if (is_array($listener) && isset($listener[0]) && is_string($listener[0])) {
            return $this->createClassListener($listener, $wildcard);
        }
        return function ($event, $payload) use ($listener, $wildcard) {
            if ($wildcard) {
                return $listener($event, $payload);
            }
            return $listener(...array_values($payload));
        };
    }
    public function createClassListener($listener, $wildcard = false)
    {
        return function ($event, $payload) use ($listener, $wildcard) {
            if ($wildcard) {
                return call_user_func($this->createClassCallable($listener), $event, $payload);
            }
            $callable = $this->createClassCallable($listener);
            return $callable(...array_values($payload));
        };
    }
    protected function createClassCallable($listener)
    {
        [$class, $method] = is_array($listener) ? $listener : $this->parseClassCallable($listener);
        if (!method_exists($class, $method)) {
            $method = '__invoke';
        }
        if ($this->handlerShouldBeQueued($class)) {
            return $this->createQueuedHandlerCallable($class, $method);
        }
        $listener = $this->container->make($class);
        return $this->handlerShouldBeDispatchedAfterDatabaseTransactions($listener) ? $this->createCallbackForListenerRunningAfterCommits($listener, $method) : [$listener, $method];
    }
    protected function parseClassCallable($listener)
    {
        return Str::parseCallback($listener, 'handle');
    }
    protected function handlerShouldBeQueued($class)
    {
        try {
            return (new ReflectionClass($class))->implementsInterface(ShouldQueue::class);
        } catch (Exception) {
            return false;
        }
    }
    protected function createQueuedHandlerCallable($class, $method)
    {
        return function () use ($class, $method) {
            $arguments = array_map(function ($a) {
                return is_object($a) ? clone $a : $a;
            }, func_get_args());
            if ($this->handlerWantsToBeQueued($class, $arguments)) {
                $this->queueHandler($class, $method, $arguments);
            }
        };
    }
    protected function handlerShouldBeDispatchedAfterDatabaseTransactions($listener)
    {
        return (($listener->afterCommit ?? null) || $listener instanceof ShouldHandleEventsAfterCommit) && $this->resolveTransactionManager();
    }
    protected function createCallbackForListenerRunningAfterCommits($listener, $method)
    {
        return function () use ($method, $listener) {
            $payload = func_get_args();
            $this->resolveTransactionManager()->addCallback(function () use ($listener, $method, $payload) {
                $listener->{$method}(...$payload);
            });
        };
    }
    protected function handlerWantsToBeQueued($class, $arguments)
    {
        $instance = $this->container->make($class);
        if (method_exists($instance, 'shouldQueue')) {
            return $instance->shouldQueue($arguments[0]);
        }
        return true;
    }
    protected function queueHandler($class, $method, $arguments)
    {
        [$listener, $job] = $this->createListenerAndJob($class, $method, $arguments);
        $connection = $this->resolveQueue()->connection(method_exists($listener, 'viaConnection') ? isset($arguments[0]) ? $listener->viaConnection($arguments[0]) : $listener->viaConnection() : $listener->connection ?? null);
        $queue = method_exists($listener, 'viaQueue') ? isset($arguments[0]) ? $listener->viaQueue($arguments[0]) : $listener->viaQueue() : $listener->queue ?? null;
        $delay = method_exists($listener, 'withDelay') ? isset($arguments[0]) ? $listener->withDelay($arguments[0]) : $listener->withDelay() : $listener->delay ?? null;
        is_null($delay) ? $connection->pushOn($queue, $job) : $connection->laterOn($queue, $delay, $job);
    }
    protected function createListenerAndJob($class, $method, $arguments)
    {
        $listener = (new ReflectionClass($class))->newInstanceWithoutConstructor();
        return [$listener, $this->propagateListenerOptions($listener, new CallQueuedListener($class, $method, $arguments))];
    }
    protected function propagateListenerOptions($listener, $job)
    {
        return tap($job, function ($job) use ($listener) {
            $data = array_values($job->data);
            if ($listener instanceof ShouldQueueAfterCommit) {
                $job->afterCommit = true;
            } else {
                $job->afterCommit = property_exists($listener, 'afterCommit') ? $listener->afterCommit : null;
            }
            $job->backoff = method_exists($listener, 'backoff') ? $listener->backoff(...$data) : $listener->backoff ?? null;
            $job->maxExceptions = $listener->maxExceptions ?? null;
            $job->retryUntil = method_exists($listener, 'retryUntil') ? $listener->retryUntil(...$data) : null;
            $job->shouldBeEncrypted = $listener instanceof ShouldBeEncrypted;
            $job->timeout = $listener->timeout ?? null;
            $job->failOnTimeout = $listener->failOnTimeout ?? false;
            $job->tries = $listener->tries ?? null;
            $job->through(array_merge(method_exists($listener, 'middleware') ? $listener->middleware(...$data) : [], $listener->middleware ?? []));
        });
    }
    public function forget($event)
    {
        if (str_contains($event, '*')) {
            unset($this->wildcards[$event]);
        } else {
            unset($this->listeners[$event]);
        }
        foreach ($this->wildcardsCache as $key => $listeners) {
            if (Str::is($event, $key)) {
                unset($this->wildcardsCache[$key]);
            }
        }
    }
    public function forgetPushed()
    {
        foreach ($this->listeners as $key => $value) {
            if (str_ends_with($key, '_pushed')) {
                $this->forget($key);
            }
        }
    }
    protected function resolveQueue()
    {
        return call_user_func($this->queueResolver);
    }
    public function setQueueResolver(callable $resolver)
    {
        $this->queueResolver = $resolver;
        return $this;
    }
    protected function resolveTransactionManager()
    {
        return call_user_func($this->transactionManagerResolver);
    }
    public function setTransactionManagerResolver(callable $resolver)
    {
        $this->transactionManagerResolver = $resolver;
        return $this;
    }
    public function getRawListeners()
    {
        return $this->listeners;
    }
}
}

namespace Illuminate\Events {
use Illuminate\Contracts\Queue\Factory as QueueFactoryContract;
use Illuminate\Support\ServiceProvider;
class EventServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('events', function ($app) {
            return (new Dispatcher($app))->setQueueResolver(function () use ($app) {
                return $app->make(QueueFactoryContract::class);
            })->setTransactionManagerResolver(function () use ($app) {
                return $app->bound('db.transactions') ? $app->make('db.transactions') : null;
            });
        });
    }
}
}

namespace Illuminate\Validation {
use BadMethodCallException;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Contracts\Validation\DataAwareRule;
use Illuminate\Contracts\Validation\ImplicitRule;
use Illuminate\Contracts\Validation\Rule as RuleContract;
use Illuminate\Contracts\Validation\Validator as ValidatorContract;
use Illuminate\Contracts\Validation\ValidatorAwareRule;
use Illuminate\Support\Arr;
use Illuminate\Support\Fluent;
use Illuminate\Support\MessageBag;
use Illuminate\Support\Str;
use Illuminate\Support\ValidatedInput;
use InvalidArgumentException;
use RuntimeException;
use stdClass;
use Symfony\Component\HttpFoundation\File\UploadedFile;
class Validator implements ValidatorContract
{
    use Concerns\FormatsMessages, Concerns\ValidatesAttributes;
    protected $translator;
    protected $container;
    protected $presenceVerifier;
    protected $failedRules = [];
    protected $excludeAttributes = [];
    protected $messages;
    protected $data;
    protected $initialRules;
    protected $rules;
    protected $currentRule;
    protected $implicitAttributes = [];
    protected $implicitAttributesFormatter;
    protected $distinctValues = [];
    protected $after = [];
    public $customMessages = [];
    public $fallbackMessages = [];
    public $customAttributes = [];
    public $customValues = [];
    protected $stopOnFirstFailure = false;
    public $excludeUnvalidatedArrayKeys = false;
    public $extensions = [];
    public $replacers = [];
    protected $fileRules = ['Between', 'Dimensions', 'Extensions', 'File', 'Image', 'Max', 'Mimes', 'Mimetypes', 'Min', 'Size'];
    protected $implicitRules = ['Accepted', 'AcceptedIf', 'Declined', 'DeclinedIf', 'Filled', 'Missing', 'MissingIf', 'MissingUnless', 'MissingWith', 'MissingWithAll', 'Present', 'PresentIf', 'PresentUnless', 'PresentWith', 'PresentWithAll', 'Required', 'RequiredIf', 'RequiredIfAccepted', 'RequiredUnless', 'RequiredWith', 'RequiredWithAll', 'RequiredWithout', 'RequiredWithoutAll'];
    protected $dependentRules = ['After', 'AfterOrEqual', 'Before', 'BeforeOrEqual', 'Confirmed', 'Different', 'ExcludeIf', 'ExcludeUnless', 'ExcludeWith', 'ExcludeWithout', 'Gt', 'Gte', 'Lt', 'Lte', 'AcceptedIf', 'DeclinedIf', 'RequiredIf', 'RequiredIfAccepted', 'RequiredUnless', 'RequiredWith', 'RequiredWithAll', 'RequiredWithout', 'RequiredWithoutAll', 'PresentIf', 'PresentUnless', 'PresentWith', 'PresentWithAll', 'Prohibited', 'ProhibitedIf', 'ProhibitedUnless', 'Prohibits', 'MissingIf', 'MissingUnless', 'MissingWith', 'MissingWithAll', 'Same', 'Unique'];
    protected $excludeRules = ['Exclude', 'ExcludeIf', 'ExcludeUnless', 'ExcludeWith', 'ExcludeWithout'];
    protected $sizeRules = ['Size', 'Between', 'Min', 'Max', 'Gt', 'Lt', 'Gte', 'Lte'];
    protected $numericRules = ['Numeric', 'Integer', 'Decimal'];
    protected $defaultNumericRules = ['Numeric', 'Integer', 'Decimal'];
    protected $dotPlaceholder;
    protected $exception = ValidationException::class;
    protected $ensureExponentWithinAllowedRangeUsing;
    public function __construct(Translator $translator, array $data, array $rules, array $messages = [], array $attributes = [])
    {
        $this->dotPlaceholder = Str::random();
        $this->initialRules = $rules;
        $this->translator = $translator;
        $this->customMessages = $messages;
        $this->data = $this->parseData($data);
        $this->customAttributes = $attributes;
        $this->setRules($rules);
    }
    public function parseData(array $data)
    {
        $newData = [];
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $value = $this->parseData($value);
            }
            $key = str_replace(['.', '*'], [$this->dotPlaceholder, '__asterisk__'], $key);
            $newData[$key] = $value;
        }
        return $newData;
    }
    protected function replacePlaceholders($data)
    {
        $originalData = [];
        foreach ($data as $key => $value) {
            $originalData[$this->replacePlaceholderInString($key)] = is_array($value) ? $this->replacePlaceholders($value) : $value;
        }
        return $originalData;
    }
    protected function replacePlaceholderInString(string $value)
    {
        return str_replace([$this->dotPlaceholder, '__asterisk__'], ['.', '*'], $value);
    }
    public function after($callback)
    {
        if (is_array($callback) && !is_callable($callback)) {
            foreach ($callback as $rule) {
                $this->after(method_exists($rule, 'after') ? $rule->after(...) : $rule);
            }
            return $this;
        }
        $this->after[] = fn() => $callback($this);
        return $this;
    }
    public function passes()
    {
        $this->messages = new MessageBag();
        [$this->distinctValues, $this->failedRules] = [[], []];
        foreach ($this->rules as $attribute => $rules) {
            if ($this->shouldBeExcluded($attribute)) {
                $this->removeAttribute($attribute);
                continue;
            }
            if ($this->stopOnFirstFailure && $this->messages->isNotEmpty()) {
                break;
            }
            foreach ($rules as $rule) {
                $this->validateAttribute($attribute, $rule);
                if ($this->shouldBeExcluded($attribute)) {
                    break;
                }
                if ($this->shouldStopValidating($attribute)) {
                    break;
                }
            }
        }
        foreach ($this->rules as $attribute => $rules) {
            if ($this->shouldBeExcluded($attribute)) {
                $this->removeAttribute($attribute);
            }
        }
        foreach ($this->after as $after) {
            $after();
        }
        return $this->messages->isEmpty();
    }
    public function fails()
    {
        return !$this->passes();
    }
    protected function shouldBeExcluded($attribute)
    {
        foreach ($this->excludeAttributes as $excludeAttribute) {
            if ($attribute === $excludeAttribute || Str::startsWith($attribute, $excludeAttribute . '.')) {
                return true;
            }
        }
        return false;
    }
    protected function removeAttribute($attribute)
    {
        Arr::forget($this->data, $attribute);
        Arr::forget($this->rules, $attribute);
    }
    public function validate()
    {
        throw_if($this->fails(), $this->exception, $this);
        return $this->validated();
    }
    public function validateWithBag(string $errorBag)
    {
        try {
            return $this->validate();
        } catch (ValidationException $e) {
            $e->errorBag = $errorBag;
            throw $e;
        }
    }
    public function safe(?array $keys = null)
    {
        return is_array($keys) ? (new ValidatedInput($this->validated()))->only($keys) : new ValidatedInput($this->validated());
    }
    public function validated()
    {
        throw_if($this->invalid(), $this->exception, $this);
        $results = [];
        $missingValue = new stdClass();
        foreach ($this->getRules() as $key => $rules) {
            $value = data_get($this->getData(), $key, $missingValue);
            if ($this->excludeUnvalidatedArrayKeys && in_array('array', $rules) && $value !== null && !empty(preg_grep('/^' . preg_quote($key, '/') . '\.+/', array_keys($this->getRules())))) {
                continue;
            }
            if ($value !== $missingValue) {
                Arr::set($results, $key, $value);
            }
        }
        return $this->replacePlaceholders($results);
    }
    protected function validateAttribute($attribute, $rule)
    {
        $this->currentRule = $rule;
        [$rule, $parameters] = ValidationRuleParser::parse($rule);
        if ($rule === '') {
            return;
        }
        if ($this->dependsOnOtherFields($rule)) {
            $parameters = $this->replaceDotInParameters($parameters);
            if ($keys = $this->getExplicitKeys($attribute)) {
                $parameters = $this->replaceAsterisksInParameters($parameters, $keys);
            }
        }
        $value = $this->getValue($attribute);
        if ($value instanceof UploadedFile && !$value->isValid() && $this->hasRule($attribute, array_merge($this->fileRules, $this->implicitRules))) {
            return $this->addFailure($attribute, 'uploaded', []);
        }
        $validatable = $this->isValidatable($rule, $attribute, $value);
        if ($rule instanceof RuleContract) {
            return $validatable ? $this->validateUsingCustomRule($attribute, $value, $rule) : null;
        }
        $method = "validate{$rule}";
        $this->numericRules = $this->defaultNumericRules;
        if ($validatable && !$this->{$method}($attribute, $value, $parameters, $this)) {
            $this->addFailure($attribute, $rule, $parameters);
        }
    }
    protected function dependsOnOtherFields($rule)
    {
        return in_array($rule, $this->dependentRules);
    }
    protected function getExplicitKeys($attribute)
    {
        $pattern = str_replace('\*', '([^\.]+)', preg_quote($this->getPrimaryAttribute($attribute), '/'));
        if (preg_match('/^' . $pattern . '/', $attribute, $keys)) {
            array_shift($keys);
            return $keys;
        }
        return [];
    }
    protected function getPrimaryAttribute($attribute)
    {
        foreach ($this->implicitAttributes as $unparsed => $parsed) {
            if (in_array($attribute, $parsed, true)) {
                return $unparsed;
            }
        }
        return $attribute;
    }
    protected function replaceDotInParameters(array $parameters)
    {
        return array_map(function ($field) {
            return str_replace('\.', $this->dotPlaceholder, $field);
        }, $parameters);
    }
    protected function replaceAsterisksInParameters(array $parameters, array $keys)
    {
        return array_map(function ($field) use ($keys) {
            return vsprintf(str_replace('*', '%s', $field), $keys);
        }, $parameters);
    }
    protected function isValidatable($rule, $attribute, $value)
    {
        if (in_array($rule, $this->excludeRules)) {
            return true;
        }
        return $this->presentOrRuleIsImplicit($rule, $attribute, $value) && $this->passesOptionalCheck($attribute) && $this->isNotNullIfMarkedAsNullable($rule, $attribute) && $this->hasNotFailedPreviousRuleIfPresenceRule($rule, $attribute);
    }
    protected function presentOrRuleIsImplicit($rule, $attribute, $value)
    {
        if (is_string($value) && trim($value) === '') {
            return $this->isImplicit($rule);
        }
        return $this->validatePresent($attribute, $value) || $this->isImplicit($rule);
    }
    protected function isImplicit($rule)
    {
        return $rule instanceof ImplicitRule || in_array($rule, $this->implicitRules);
    }
    protected function passesOptionalCheck($attribute)
    {
        if (!$this->hasRule($attribute, ['Sometimes'])) {
            return true;
        }
        $data = ValidationData::initializeAndGatherData($attribute, $this->data);
        return array_key_exists($attribute, $data) || array_key_exists($attribute, $this->data);
    }
    protected function isNotNullIfMarkedAsNullable($rule, $attribute)
    {
        if ($this->isImplicit($rule) || !$this->hasRule($attribute, ['Nullable'])) {
            return true;
        }
        return !is_null(Arr::get($this->data, $attribute, 0));
    }
    protected function hasNotFailedPreviousRuleIfPresenceRule($rule, $attribute)
    {
        return in_array($rule, ['Unique', 'Exists']) ? !$this->messages->has($attribute) : true;
    }
    protected function validateUsingCustomRule($attribute, $value, $rule)
    {
        $attribute = $this->replacePlaceholderInString($attribute);
        $value = is_array($value) ? $this->replacePlaceholders($value) : $value;
        if ($rule instanceof ValidatorAwareRule) {
            $rule->setValidator($this);
        }
        if ($rule instanceof DataAwareRule) {
            $rule->setData($this->data);
        }
        if (!$rule->passes($attribute, $value)) {
            $ruleClass = $rule instanceof InvokableValidationRule ? get_class($rule->invokable()) : get_class($rule);
            $this->failedRules[$attribute][$ruleClass] = [];
            $messages = $this->getFromLocalArray($attribute, $ruleClass) ?? $rule->message();
            $messages = $messages ? (array) $messages : [$ruleClass];
            foreach ($messages as $key => $message) {
                $key = is_string($key) ? $key : $attribute;
                $this->messages->add($key, $this->makeReplacements($message, $key, $ruleClass, []));
            }
        }
    }
    protected function shouldStopValidating($attribute)
    {
        $cleanedAttribute = $this->replacePlaceholderInString($attribute);
        if ($this->hasRule($attribute, ['Bail'])) {
            return $this->messages->has($cleanedAttribute);
        }
        if (isset($this->failedRules[$cleanedAttribute]) && array_key_exists('uploaded', $this->failedRules[$cleanedAttribute])) {
            return true;
        }
        return $this->hasRule($attribute, $this->implicitRules) && isset($this->failedRules[$cleanedAttribute]) && array_intersect(array_keys($this->failedRules[$cleanedAttribute]), $this->implicitRules);
    }
    public function addFailure($attribute, $rule, $parameters = [])
    {
        if (!$this->messages) {
            $this->passes();
        }
        $attributeWithPlaceholders = $attribute;
        $attribute = $this->replacePlaceholderInString($attribute);
        if (in_array($rule, $this->excludeRules)) {
            return $this->excludeAttribute($attribute);
        }
        $this->messages->add($attribute, $this->makeReplacements($this->getMessage($attributeWithPlaceholders, $rule), $attribute, $rule, $parameters));
        $this->failedRules[$attribute][$rule] = $parameters;
    }
    protected function excludeAttribute(string $attribute)
    {
        $this->excludeAttributes[] = $attribute;
        $this->excludeAttributes = array_unique($this->excludeAttributes);
    }
    public function valid()
    {
        if (!$this->messages) {
            $this->passes();
        }
        return array_diff_key($this->data, $this->attributesThatHaveMessages());
    }
    public function invalid()
    {
        if (!$this->messages) {
            $this->passes();
        }
        $invalid = array_intersect_key($this->data, $this->attributesThatHaveMessages());
        $result = [];
        $failed = Arr::only(Arr::dot($invalid), array_keys($this->failed()));
        foreach ($failed as $key => $failure) {
            Arr::set($result, $key, $failure);
        }
        return $result;
    }
    protected function attributesThatHaveMessages()
    {
        return collect($this->messages()->toArray())->map(function ($message, $key) {
            return explode('.', $key)[0];
        })->unique()->flip()->all();
    }
    public function failed()
    {
        return $this->failedRules;
    }
    public function messages()
    {
        if (!$this->messages) {
            $this->passes();
        }
        return $this->messages;
    }
    public function errors()
    {
        return $this->messages();
    }
    public function getMessageBag()
    {
        return $this->messages();
    }
    public function hasRule($attribute, $rules)
    {
        return !is_null($this->getRule($attribute, $rules));
    }
    protected function getRule($attribute, $rules)
    {
        if (!array_key_exists($attribute, $this->rules)) {
            return;
        }
        $rules = (array) $rules;
        foreach ($this->rules[$attribute] as $rule) {
            [$rule, $parameters] = ValidationRuleParser::parse($rule);
            if (in_array($rule, $rules)) {
                return [$rule, $parameters];
            }
        }
    }
    public function attributes()
    {
        return $this->getData();
    }
    public function getData()
    {
        return $this->data;
    }
    public function setData(array $data)
    {
        $this->data = $this->parseData($data);
        $this->setRules($this->initialRules);
        return $this;
    }
    public function getValue($attribute)
    {
        return Arr::get($this->data, $attribute);
    }
    public function setValue($attribute, $value)
    {
        Arr::set($this->data, $attribute, $value);
    }
    public function getRules()
    {
        return $this->rules;
    }
    public function getRulesWithoutPlaceholders()
    {
        return collect($this->rules)->mapWithKeys(fn($value, $key) => [str_replace($this->dotPlaceholder, '\.', $key) => $value])->all();
    }
    public function setRules(array $rules)
    {
        $rules = collect($rules)->mapWithKeys(function ($value, $key) {
            return [str_replace('\.', $this->dotPlaceholder, $key) => $value];
        })->toArray();
        $this->initialRules = $rules;
        $this->rules = [];
        $this->addRules($rules);
        return $this;
    }
    public function addRules($rules)
    {
        $response = (new ValidationRuleParser($this->data))->explode(ValidationRuleParser::filterConditionalRules($rules, $this->data));
        $this->rules = array_merge_recursive($this->rules, $response->rules);
        $this->implicitAttributes = array_merge($this->implicitAttributes, $response->implicitAttributes);
    }
    public function sometimes($attribute, $rules, callable $callback)
    {
        $payload = new Fluent($this->data);
        foreach ((array) $attribute as $key) {
            $response = (new ValidationRuleParser($this->data))->explode([$key => $rules]);
            $this->implicitAttributes = array_merge($response->implicitAttributes, $this->implicitAttributes);
            foreach ($response->rules as $ruleKey => $ruleValue) {
                if ($callback($payload, $this->dataForSometimesIteration($ruleKey, !str_ends_with($key, '.*')))) {
                    $this->addRules([$ruleKey => $ruleValue]);
                }
            }
        }
        return $this;
    }
    private function dataForSometimesIteration(string $attribute, $removeLastSegmentOfAttribute)
    {
        $lastSegmentOfAttribute = strrchr($attribute, '.');
        $attribute = $lastSegmentOfAttribute && $removeLastSegmentOfAttribute ? Str::replaceLast($lastSegmentOfAttribute, '', $attribute) : $attribute;
        return is_array($data = data_get($this->data, $attribute)) ? new Fluent($data) : $data;
    }
    public function stopOnFirstFailure($stopOnFirstFailure = true)
    {
        $this->stopOnFirstFailure = $stopOnFirstFailure;
        return $this;
    }
    public function addExtensions(array $extensions)
    {
        if ($extensions) {
            $keys = array_map([Str::class, 'snake'], array_keys($extensions));
            $extensions = array_combine($keys, array_values($extensions));
        }
        $this->extensions = array_merge($this->extensions, $extensions);
    }
    public function addImplicitExtensions(array $extensions)
    {
        $this->addExtensions($extensions);
        foreach ($extensions as $rule => $extension) {
            $this->implicitRules[] = Str::studly($rule);
        }
    }
    public function addDependentExtensions(array $extensions)
    {
        $this->addExtensions($extensions);
        foreach ($extensions as $rule => $extension) {
            $this->dependentRules[] = Str::studly($rule);
        }
    }
    public function addExtension($rule, $extension)
    {
        $this->extensions[Str::snake($rule)] = $extension;
    }
    public function addImplicitExtension($rule, $extension)
    {
        $this->addExtension($rule, $extension);
        $this->implicitRules[] = Str::studly($rule);
    }
    public function addDependentExtension($rule, $extension)
    {
        $this->addExtension($rule, $extension);
        $this->dependentRules[] = Str::studly($rule);
    }
    public function addReplacers(array $replacers)
    {
        if ($replacers) {
            $keys = array_map([Str::class, 'snake'], array_keys($replacers));
            $replacers = array_combine($keys, array_values($replacers));
        }
        $this->replacers = array_merge($this->replacers, $replacers);
    }
    public function addReplacer($rule, $replacer)
    {
        $this->replacers[Str::snake($rule)] = $replacer;
    }
    public function setCustomMessages(array $messages)
    {
        $this->customMessages = array_merge($this->customMessages, $messages);
        return $this;
    }
    public function setAttributeNames(array $attributes)
    {
        $this->customAttributes = $attributes;
        return $this;
    }
    public function addCustomAttributes(array $attributes)
    {
        $this->customAttributes = array_merge($this->customAttributes, $attributes);
        return $this;
    }
    public function setImplicitAttributesFormatter(?callable $formatter = null)
    {
        $this->implicitAttributesFormatter = $formatter;
        return $this;
    }
    public function setValueNames(array $values)
    {
        $this->customValues = $values;
        return $this;
    }
    public function addCustomValues(array $customValues)
    {
        $this->customValues = array_merge($this->customValues, $customValues);
        return $this;
    }
    public function setFallbackMessages(array $messages)
    {
        $this->fallbackMessages = $messages;
    }
    public function getPresenceVerifier($connection = null)
    {
        if (!isset($this->presenceVerifier)) {
            throw new RuntimeException('Presence verifier has not been set.');
        }
        if ($this->presenceVerifier instanceof DatabasePresenceVerifierInterface) {
            $this->presenceVerifier->setConnection($connection);
        }
        return $this->presenceVerifier;
    }
    public function setPresenceVerifier(PresenceVerifierInterface $presenceVerifier)
    {
        $this->presenceVerifier = $presenceVerifier;
    }
    public function getException()
    {
        return $this->exception;
    }
    public function setException($exception)
    {
        if (!is_a($exception, ValidationException::class, true)) {
            throw new InvalidArgumentException(sprintf('Exception [%s] is invalid. It must extend [%s].', $exception, ValidationException::class));
        }
        $this->exception = $exception;
        return $this;
    }
    public function ensureExponentWithinAllowedRangeUsing($callback)
    {
        $this->ensureExponentWithinAllowedRangeUsing = $callback;
        return $this;
    }
    public function getTranslator()
    {
        return $this->translator;
    }
    public function setTranslator(Translator $translator)
    {
        $this->translator = $translator;
    }
    public function setContainer(Container $container)
    {
        $this->container = $container;
    }
    protected function callExtension($rule, $parameters)
    {
        $callback = $this->extensions[$rule];
        if (is_callable($callback)) {
            return $callback(...array_values($parameters));
        } elseif (is_string($callback)) {
            return $this->callClassBasedExtension($callback, $parameters);
        }
    }
    protected function callClassBasedExtension($callback, $parameters)
    {
        [$class, $method] = Str::parseCallback($callback, 'validate');
        return $this->container->make($class)->{$method}(...array_values($parameters));
    }
    public function __call($method, $parameters)
    {
        $rule = Str::snake(substr($method, 8));
        if (isset($this->extensions[$rule])) {
            return $this->callExtension($rule, $parameters);
        }
        throw new BadMethodCallException(sprintf('Method %s::%s does not exist.', static::class, $method));
    }
}
}

namespace Illuminate\Validation {
use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Contracts\Validation\UncompromisedVerifier;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\ServiceProvider;
class ValidationServiceProvider extends ServiceProvider implements DeferrableProvider
{
    public function register()
    {
        $this->registerPresenceVerifier();
        $this->registerUncompromisedVerifier();
        $this->registerValidationFactory();
    }
    protected function registerValidationFactory()
    {
        $this->app->singleton('validator', function ($app) {
            $validator = new Factory($app['translator'], $app);
            if (isset($app['db'], $app['validation.presence'])) {
                $validator->setPresenceVerifier($app['validation.presence']);
            }
            return $validator;
        });
    }
    protected function registerPresenceVerifier()
    {
        $this->app->singleton('validation.presence', function ($app) {
            return new DatabasePresenceVerifier($app['db']);
        });
    }
    protected function registerUncompromisedVerifier()
    {
        $this->app->singleton(UncompromisedVerifier::class, function ($app) {
            return new NotPwnedVerifier($app[HttpFactory::class]);
        });
    }
    public function provides()
    {
        return ['validator', 'validation.presence', UncompromisedVerifier::class];
    }
}
}

namespace Illuminate\Validation {
use Closure;
use Illuminate\Database\ConnectionResolverInterface;
class DatabasePresenceVerifier implements DatabasePresenceVerifierInterface
{
    protected $db;
    protected $connection;
    public function __construct(ConnectionResolverInterface $db)
    {
        $this->db = $db;
    }
    public function getCount($collection, $column, $value, $excludeId = null, $idColumn = null, array $extra = [])
    {
        $query = $this->table($collection)->where($column, '=', $value);
        if (!is_null($excludeId) && $excludeId !== 'NULL') {
            $query->where($idColumn ?: 'id', '<>', $excludeId);
        }
        return $this->addConditions($query, $extra)->count();
    }
    public function getMultiCount($collection, $column, array $values, array $extra = [])
    {
        $query = $this->table($collection)->whereIn($column, $values);
        return $this->addConditions($query, $extra)->distinct()->count($column);
    }
    protected function addConditions($query, $conditions)
    {
        foreach ($conditions as $key => $value) {
            if ($value instanceof Closure) {
                $query->where(function ($query) use ($value) {
                    $value($query);
                });
            } else {
                $this->addWhere($query, $key, $value);
            }
        }
        return $query;
    }
    protected function addWhere($query, $key, $extraValue)
    {
        if ($extraValue === 'NULL') {
            $query->whereNull($key);
        } elseif ($extraValue === 'NOT_NULL') {
            $query->whereNotNull($key);
        } elseif (str_starts_with($extraValue, '!')) {
            $query->where($key, '!=', mb_substr($extraValue, 1));
        } else {
            $query->where($key, $extraValue);
        }
    }
    protected function table($table)
    {
        return $this->db->connection($this->connection)->table($table)->useWritePdo();
    }
    public function setConnection($connection)
    {
        $this->connection = $connection;
    }
}
}

namespace Illuminate\Validation {
use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Contracts\Validation\Factory as FactoryContract;
use Illuminate\Support\Str;
class Factory implements FactoryContract
{
    protected $translator;
    protected $verifier;
    protected $container;
    protected $extensions = [];
    protected $implicitExtensions = [];
    protected $dependentExtensions = [];
    protected $replacers = [];
    protected $fallbackMessages = [];
    protected $excludeUnvalidatedArrayKeys = true;
    protected $resolver;
    public function __construct(Translator $translator, ?Container $container = null)
    {
        $this->container = $container;
        $this->translator = $translator;
    }
    public function make(array $data, array $rules, array $messages = [], array $attributes = [])
    {
        $validator = $this->resolve($data, $rules, $messages, $attributes);
        if (!is_null($this->verifier)) {
            $validator->setPresenceVerifier($this->verifier);
        }
        if (!is_null($this->container)) {
            $validator->setContainer($this->container);
        }
        $validator->excludeUnvalidatedArrayKeys = $this->excludeUnvalidatedArrayKeys;
        $this->addExtensions($validator);
        return $validator;
    }
    public function validate(array $data, array $rules, array $messages = [], array $attributes = [])
    {
        return $this->make($data, $rules, $messages, $attributes)->validate();
    }
    protected function resolve(array $data, array $rules, array $messages, array $attributes)
    {
        if (is_null($this->resolver)) {
            return new Validator($this->translator, $data, $rules, $messages, $attributes);
        }
        return call_user_func($this->resolver, $this->translator, $data, $rules, $messages, $attributes);
    }
    protected function addExtensions(Validator $validator)
    {
        $validator->addExtensions($this->extensions);
        $validator->addImplicitExtensions($this->implicitExtensions);
        $validator->addDependentExtensions($this->dependentExtensions);
        $validator->addReplacers($this->replacers);
        $validator->setFallbackMessages($this->fallbackMessages);
    }
    public function extend($rule, $extension, $message = null)
    {
        $this->extensions[$rule] = $extension;
        if ($message) {
            $this->fallbackMessages[Str::snake($rule)] = $message;
        }
    }
    public function extendImplicit($rule, $extension, $message = null)
    {
        $this->implicitExtensions[$rule] = $extension;
        if ($message) {
            $this->fallbackMessages[Str::snake($rule)] = $message;
        }
    }
    public function extendDependent($rule, $extension, $message = null)
    {
        $this->dependentExtensions[$rule] = $extension;
        if ($message) {
            $this->fallbackMessages[Str::snake($rule)] = $message;
        }
    }
    public function replacer($rule, $replacer)
    {
        $this->replacers[$rule] = $replacer;
    }
    public function includeUnvalidatedArrayKeys()
    {
        $this->excludeUnvalidatedArrayKeys = false;
    }
    public function excludeUnvalidatedArrayKeys()
    {
        $this->excludeUnvalidatedArrayKeys = true;
    }
    public function resolver(Closure $resolver)
    {
        $this->resolver = $resolver;
    }
    public function getTranslator()
    {
        return $this->translator;
    }
    public function getPresenceVerifier()
    {
        return $this->verifier;
    }
    public function setPresenceVerifier(PresenceVerifierInterface $presenceVerifier)
    {
        $this->verifier = $presenceVerifier;
    }
    public function getContainer()
    {
        return $this->container;
    }
    public function setContainer(Container $container)
    {
        $this->container = $container;
        return $this;
    }
}
}

namespace Illuminate\Validation {
use Illuminate\Foundation\Precognition;
trait ValidatesWhenResolvedTrait
{
    public function validateResolved()
    {
        $this->prepareForValidation();
        if (!$this->passesAuthorization()) {
            $this->failedAuthorization();
        }
        $instance = $this->getValidatorInstance();
        if ($this->isPrecognitive()) {
            $instance->after(Precognition::afterValidationHook($this));
        }
        if ($instance->fails()) {
            $this->failedValidation($instance);
        }
        $this->passedValidation();
    }
    protected function prepareForValidation()
    {
    }
    protected function getValidatorInstance()
    {
        return $this->validator();
    }
    protected function passedValidation()
    {
    }
    protected function failedValidation(Validator $validator)
    {
        $exception = $validator->getException();
        throw new $exception($validator);
    }
    protected function passesAuthorization()
    {
        if (method_exists($this, 'authorize')) {
            return $this->authorize();
        }
        return true;
    }
    protected function failedAuthorization()
    {
        throw new UnauthorizedException();
    }
}
}

namespace Illuminate\Validation {
interface PresenceVerifierInterface
{
    public function getCount($collection, $column, $value, $excludeId = null, $idColumn = null, array $extra = []);
    public function getMultiCount($collection, $column, array $values, array $extra = []);
}
}

namespace Illuminate\Validation {
use Exception;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Validator as ValidatorFacade;
class ValidationException extends Exception
{
    public $validator;
    public $response;
    public $status = 422;
    public $errorBag;
    public $redirectTo;
    public function __construct($validator, $response = null, $errorBag = 'default')
    {
        parent::__construct(static::summarize($validator));
        $this->response = $response;
        $this->errorBag = $errorBag;
        $this->validator = $validator;
    }
    public static function withMessages(array $messages)
    {
        return new static(tap(ValidatorFacade::make([], []), function ($validator) use ($messages) {
            foreach ($messages as $key => $value) {
                foreach (Arr::wrap($value) as $message) {
                    $validator->errors()->add($key, $message);
                }
            }
        }));
    }
    protected static function summarize($validator)
    {
        $messages = $validator->errors()->all();
        if (!count($messages) || !is_string($messages[0])) {
            return $validator->getTranslator()->get('The given data was invalid.');
        }
        $message = array_shift($messages);
        if ($count = count($messages)) {
            $pluralized = $count === 1 ? 'error' : 'errors';
            $message .= ' ' . $validator->getTranslator()->get("(and :count more {$pluralized})", compact('count'));
        }
        return $message;
    }
    public function errors()
    {
        return $this->validator->errors()->messages();
    }
    public function status($status)
    {
        $this->status = $status;
        return $this;
    }
    public function errorBag($errorBag)
    {
        $this->errorBag = $errorBag;
        return $this;
    }
    public function redirectTo($url)
    {
        $this->redirectTo = $url;
        return $this;
    }
    public function getResponse()
    {
        return $this->response;
    }
}
}

namespace Illuminate\Pagination {
use Closure;
use Illuminate\Contracts\Support\Htmlable;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\Traits\ForwardsCalls;
use Illuminate\Support\Traits\Tappable;
use Traversable;
abstract class AbstractPaginator implements Htmlable
{
    use ForwardsCalls, Tappable;
    protected $items;
    protected $perPage;
    protected $currentPage;
    protected $path = '/';
    protected $query = [];
    protected $fragment;
    protected $pageName = 'page';
    public $onEachSide = 3;
    protected $options;
    protected static $currentPathResolver;
    protected static $currentPageResolver;
    protected static $queryStringResolver;
    protected static $viewFactoryResolver;
    public static $defaultView = 'pagination::tailwind';
    public static $defaultSimpleView = 'pagination::simple-tailwind';
    protected function isValidPageNumber($page)
    {
        return $page >= 1 && filter_var($page, FILTER_VALIDATE_INT) !== false;
    }
    public function previousPageUrl()
    {
        if ($this->currentPage() > 1) {
            return $this->url($this->currentPage() - 1);
        }
    }
    public function getUrlRange($start, $end)
    {
        return collect(range($start, $end))->mapWithKeys(function ($page) {
            return [$page => $this->url($page)];
        })->all();
    }
    public function url($page)
    {
        if ($page <= 0) {
            $page = 1;
        }
        $parameters = [$this->pageName => $page];
        if (count($this->query) > 0) {
            $parameters = array_merge($this->query, $parameters);
        }
        return $this->path() . (str_contains($this->path(), '?') ? '&' : '?') . Arr::query($parameters) . $this->buildFragment();
    }
    public function fragment($fragment = null)
    {
        if (is_null($fragment)) {
            return $this->fragment;
        }
        $this->fragment = $fragment;
        return $this;
    }
    public function appends($key, $value = null)
    {
        if (is_null($key)) {
            return $this;
        }
        if (is_array($key)) {
            return $this->appendArray($key);
        }
        return $this->addQuery($key, $value);
    }
    protected function appendArray(array $keys)
    {
        foreach ($keys as $key => $value) {
            $this->addQuery($key, $value);
        }
        return $this;
    }
    public function withQueryString()
    {
        if (isset(static::$queryStringResolver)) {
            return $this->appends(call_user_func(static::$queryStringResolver));
        }
        return $this;
    }
    protected function addQuery($key, $value)
    {
        if ($key !== $this->pageName) {
            $this->query[$key] = $value;
        }
        return $this;
    }
    protected function buildFragment()
    {
        return $this->fragment ? '#' . $this->fragment : '';
    }
    public function loadMorph($relation, $relations)
    {
        $this->getCollection()->loadMorph($relation, $relations);
        return $this;
    }
    public function loadMorphCount($relation, $relations)
    {
        $this->getCollection()->loadMorphCount($relation, $relations);
        return $this;
    }
    public function items()
    {
        return $this->items->all();
    }
    public function firstItem()
    {
        return count($this->items) > 0 ? ($this->currentPage - 1) * $this->perPage + 1 : null;
    }
    public function lastItem()
    {
        return count($this->items) > 0 ? $this->firstItem() + $this->count() - 1 : null;
    }
    public function through(callable $callback)
    {
        $this->items->transform($callback);
        return $this;
    }
    public function perPage()
    {
        return $this->perPage;
    }
    public function hasPages()
    {
        return $this->currentPage() != 1 || $this->hasMorePages();
    }
    public function onFirstPage()
    {
        return $this->currentPage() <= 1;
    }
    public function onLastPage()
    {
        return !$this->hasMorePages();
    }
    public function currentPage()
    {
        return $this->currentPage;
    }
    public function getPageName()
    {
        return $this->pageName;
    }
    public function setPageName($name)
    {
        $this->pageName = $name;
        return $this;
    }
    public function withPath($path)
    {
        return $this->setPath($path);
    }
    public function setPath($path)
    {
        $this->path = $path;
        return $this;
    }
    public function onEachSide($count)
    {
        $this->onEachSide = $count;
        return $this;
    }
    public function path()
    {
        return $this->path;
    }
    public static function resolveCurrentPath($default = '/')
    {
        if (isset(static::$currentPathResolver)) {
            return call_user_func(static::$currentPathResolver);
        }
        return $default;
    }
    public static function currentPathResolver(Closure $resolver)
    {
        static::$currentPathResolver = $resolver;
    }
    public static function resolveCurrentPage($pageName = 'page', $default = 1)
    {
        if (isset(static::$currentPageResolver)) {
            return (int) call_user_func(static::$currentPageResolver, $pageName);
        }
        return $default;
    }
    public static function currentPageResolver(Closure $resolver)
    {
        static::$currentPageResolver = $resolver;
    }
    public static function resolveQueryString($default = null)
    {
        if (isset(static::$queryStringResolver)) {
            return (static::$queryStringResolver)();
        }
        return $default;
    }
    public static function queryStringResolver(Closure $resolver)
    {
        static::$queryStringResolver = $resolver;
    }
    public static function viewFactory()
    {
        return call_user_func(static::$viewFactoryResolver);
    }
    public static function viewFactoryResolver(Closure $resolver)
    {
        static::$viewFactoryResolver = $resolver;
    }
    public static function defaultView($view)
    {
        static::$defaultView = $view;
    }
    public static function defaultSimpleView($view)
    {
        static::$defaultSimpleView = $view;
    }
    public static function useTailwind()
    {
        static::defaultView('pagination::tailwind');
        static::defaultSimpleView('pagination::simple-tailwind');
    }
    public static function useBootstrap()
    {
        static::useBootstrapFour();
    }
    public static function useBootstrapThree()
    {
        static::defaultView('pagination::default');
        static::defaultSimpleView('pagination::simple-default');
    }
    public static function useBootstrapFour()
    {
        static::defaultView('pagination::bootstrap-4');
        static::defaultSimpleView('pagination::simple-bootstrap-4');
    }
    public static function useBootstrapFive()
    {
        static::defaultView('pagination::bootstrap-5');
        static::defaultSimpleView('pagination::simple-bootstrap-5');
    }
    public function getIterator(): Traversable
    {
        return $this->items->getIterator();
    }
    public function isEmpty()
    {
        return $this->items->isEmpty();
    }
    public function isNotEmpty()
    {
        return $this->items->isNotEmpty();
    }
    public function count(): int
    {
        return $this->items->count();
    }
    public function getCollection()
    {
        return $this->items;
    }
    public function setCollection(Collection $collection)
    {
        $this->items = $collection;
        return $this;
    }
    public function getOptions()
    {
        return $this->options;
    }
    public function offsetExists($key): bool
    {
        return $this->items->has($key);
    }
    public function offsetGet($key): mixed
    {
        return $this->items->get($key);
    }
    public function offsetSet($key, $value): void
    {
        $this->items->put($key, $value);
    }
    public function offsetUnset($key): void
    {
        $this->items->forget($key);
    }
    public function toHtml()
    {
        return (string) $this->render();
    }
    public function __call($method, $parameters)
    {
        return $this->forwardCallTo($this->getCollection(), $method, $parameters);
    }
    public function __toString()
    {
        return (string) $this->render();
    }
}
}

namespace Illuminate\Pagination {
use ArrayAccess;
use Countable;
use Illuminate\Contracts\Pagination\Paginator as PaginatorContract;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Support\Collection;
use IteratorAggregate;
use JsonSerializable;
class Paginator extends AbstractPaginator implements Arrayable, ArrayAccess, Countable, IteratorAggregate, Jsonable, JsonSerializable, PaginatorContract
{
    protected $hasMore;
    public function __construct($items, $perPage, $currentPage = null, array $options = [])
    {
        $this->options = $options;
        foreach ($options as $key => $value) {
            $this->{$key} = $value;
        }
        $this->perPage = $perPage;
        $this->currentPage = $this->setCurrentPage($currentPage);
        $this->path = $this->path !== '/' ? rtrim($this->path, '/') : $this->path;
        $this->setItems($items);
    }
    protected function setCurrentPage($currentPage)
    {
        $currentPage = $currentPage ?: static::resolveCurrentPage();
        return $this->isValidPageNumber($currentPage) ? (int) $currentPage : 1;
    }
    protected function setItems($items)
    {
        $this->items = $items instanceof Collection ? $items : Collection::make($items);
        $this->hasMore = $this->items->count() > $this->perPage;
        $this->items = $this->items->slice(0, $this->perPage);
    }
    public function nextPageUrl()
    {
        if ($this->hasMorePages()) {
            return $this->url($this->currentPage() + 1);
        }
    }
    public function links($view = null, $data = [])
    {
        return $this->render($view, $data);
    }
    public function render($view = null, $data = [])
    {
        return static::viewFactory()->make($view ?: static::$defaultSimpleView, array_merge($data, ['paginator' => $this]));
    }
    public function hasMorePagesWhen($hasMore = true)
    {
        $this->hasMore = $hasMore;
        return $this;
    }
    public function hasMorePages()
    {
        return $this->hasMore;
    }
    public function toArray()
    {
        return ['current_page' => $this->currentPage(), 'data' => $this->items->toArray(), 'first_page_url' => $this->url(1), 'from' => $this->firstItem(), 'next_page_url' => $this->nextPageUrl(), 'path' => $this->path(), 'per_page' => $this->perPage(), 'prev_page_url' => $this->previousPageUrl(), 'to' => $this->lastItem()];
    }
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
    public function toJson($options = 0)
    {
        return json_encode($this->jsonSerialize(), $options);
    }
}
}

namespace Illuminate\Hashing {
use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Support\ServiceProvider;
class HashServiceProvider extends ServiceProvider implements DeferrableProvider
{
    public function register()
    {
        $this->app->singleton('hash', function ($app) {
            return new HashManager($app);
        });
        $this->app->singleton('hash.driver', function ($app) {
            return $app['hash']->driver();
        });
    }
    public function provides()
    {
        return ['hash', 'hash.driver'];
    }
}
}

namespace Illuminate\Hashing {
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use RuntimeException;
class BcryptHasher extends AbstractHasher implements HasherContract
{
    protected $rounds = 12;
    protected $verifyAlgorithm = false;
    public function __construct(array $options = [])
    {
        $this->rounds = $options['rounds'] ?? $this->rounds;
        $this->verifyAlgorithm = $options['verify'] ?? $this->verifyAlgorithm;
    }
    public function make($value, array $options = [])
    {
        $hash = password_hash($value, PASSWORD_BCRYPT, ['cost' => $this->cost($options)]);
        if ($hash === false) {
            throw new RuntimeException('Bcrypt hashing not supported.');
        }
        return $hash;
    }
    public function check($value, $hashedValue, array $options = [])
    {
        if ($this->verifyAlgorithm && !$this->isUsingCorrectAlgorithm($hashedValue)) {
            throw new RuntimeException('This password does not use the Bcrypt algorithm.');
        }
        return parent::check($value, $hashedValue, $options);
    }
    public function needsRehash($hashedValue, array $options = [])
    {
        return password_needs_rehash($hashedValue, PASSWORD_BCRYPT, ['cost' => $this->cost($options)]);
    }
    public function verifyConfiguration($value)
    {
        return $this->isUsingCorrectAlgorithm($value) && $this->isUsingValidOptions($value);
    }
    protected function isUsingCorrectAlgorithm($hashedValue)
    {
        return $this->info($hashedValue)['algoName'] === 'bcrypt';
    }
    protected function isUsingValidOptions($hashedValue)
    {
        ['options' => $options] = $this->info($hashedValue);
        if (!is_int($options['cost'] ?? null)) {
            return false;
        }
        if ($options['cost'] > $this->rounds) {
            return false;
        }
        return true;
    }
    public function setRounds($rounds)
    {
        $this->rounds = (int) $rounds;
        return $this;
    }
    protected function cost(array $options = [])
    {
        return $options['rounds'] ?? $this->rounds;
    }
}
}

namespace Illuminate\Config {
use ArrayAccess;
use Illuminate\Contracts\Config\Repository as ConfigContract;
use Illuminate\Support\Arr;
use Illuminate\Support\Traits\Macroable;
class Repository implements ArrayAccess, ConfigContract
{
    use Macroable;
    protected $items = [];
    public function __construct(array $items = [])
    {
        $this->items = $items;
    }
    public function has($key)
    {
        return Arr::has($this->items, $key);
    }
    public function get($key, $default = null)
    {
        if (is_array($key)) {
            return $this->getMany($key);
        }
        return Arr::get($this->items, $key, $default);
    }
    public function getMany($keys)
    {
        $config = [];
        foreach ($keys as $key => $default) {
            if (is_numeric($key)) {
                [$key, $default] = [$default, null];
            }
            $config[$key] = Arr::get($this->items, $key, $default);
        }
        return $config;
    }
    public function set($key, $value = null)
    {
        $keys = is_array($key) ? $key : [$key => $value];
        foreach ($keys as $key => $value) {
            Arr::set($this->items, $key, $value);
        }
    }
    public function prepend($key, $value)
    {
        $array = $this->get($key, []);
        array_unshift($array, $value);
        $this->set($key, $array);
    }
    public function push($key, $value)
    {
        $array = $this->get($key, []);
        $array[] = $value;
        $this->set($key, $array);
    }
    public function all()
    {
        return $this->items;
    }
    public function offsetExists($key): bool
    {
        return $this->has($key);
    }
    public function offsetGet($key): mixed
    {
        return $this->get($key);
    }
    public function offsetSet($key, $value): void
    {
        $this->set($key, $value);
    }
    public function offsetUnset($key): void
    {
        $this->set($key, null);
    }
}
}

namespace Illuminate\Filesystem {
use ErrorException;
use FilesystemIterator;
use Illuminate\Contracts\Filesystem\FileNotFoundException;
use Illuminate\Support\LazyCollection;
use Illuminate\Support\Traits\Conditionable;
use Illuminate\Support\Traits\Macroable;
use RuntimeException;
use SplFileObject;
use Symfony\Component\Filesystem\Filesystem as SymfonyFilesystem;
use Symfony\Component\Finder\Finder;
use Symfony\Component\Mime\MimeTypes;
class Filesystem
{
    use Conditionable, Macroable;
    public function exists($path)
    {
        return file_exists($path);
    }
    public function missing($path)
    {
        return !$this->exists($path);
    }
    public function get($path, $lock = false)
    {
        if ($this->isFile($path)) {
            return $lock ? $this->sharedGet($path) : file_get_contents($path);
        }
        throw new FileNotFoundException("File does not exist at path {$path}.");
    }
    public function json($path, $flags = 0, $lock = false)
    {
        return json_decode($this->get($path, $lock), true, 512, $flags);
    }
    public function sharedGet($path)
    {
        $contents = '';
        $handle = fopen($path, 'rb');
        if ($handle) {
            try {
                if (flock($handle, LOCK_SH)) {
                    clearstatcache(true, $path);
                    $contents = fread($handle, $this->size($path) ?: 1);
                    flock($handle, LOCK_UN);
                }
            } finally {
                fclose($handle);
            }
        }
        return $contents;
    }
    public function getRequire($path, array $data = [])
    {
        if ($this->isFile($path)) {
            $__path = $path;
            $__data = $data;
            return (static function () use ($__path, $__data) {
                extract($__data, EXTR_SKIP);
                return require $__path;
            })();
        }
        throw new FileNotFoundException("File does not exist at path {$path}.");
    }
    public function requireOnce($path, array $data = [])
    {
        if ($this->isFile($path)) {
            $__path = $path;
            $__data = $data;
            return (static function () use ($__path, $__data) {
                extract($__data, EXTR_SKIP);
                return require_once $__path;
            })();
        }
        throw new FileNotFoundException("File does not exist at path {$path}.");
    }
    public function lines($path)
    {
        if (!$this->isFile($path)) {
            throw new FileNotFoundException("File does not exist at path {$path}.");
        }
        return LazyCollection::make(function () use ($path) {
            $file = new SplFileObject($path);
            $file->setFlags(SplFileObject::DROP_NEW_LINE);
            while (!$file->eof()) {
                yield $file->fgets();
            }
        });
    }
    public function hash($path, $algorithm = 'md5')
    {
        return hash_file($algorithm, $path);
    }
    public function put($path, $contents, $lock = false)
    {
        return file_put_contents($path, $contents, $lock ? LOCK_EX : 0);
    }
    public function replace($path, $content, $mode = null)
    {
        clearstatcache(true, $path);
        $path = realpath($path) ?: $path;
        $tempPath = tempnam(dirname($path), basename($path));
        if (!is_null($mode)) {
            chmod($tempPath, $mode);
        } else {
            chmod($tempPath, 0777 - umask());
        }
        file_put_contents($tempPath, $content);
        rename($tempPath, $path);
    }
    public function replaceInFile($search, $replace, $path)
    {
        file_put_contents($path, str_replace($search, $replace, file_get_contents($path)));
    }
    public function prepend($path, $data)
    {
        if ($this->exists($path)) {
            return $this->put($path, $data . $this->get($path));
        }
        return $this->put($path, $data);
    }
    public function append($path, $data, $lock = false)
    {
        return file_put_contents($path, $data, FILE_APPEND | ($lock ? LOCK_EX : 0));
    }
    public function chmod($path, $mode = null)
    {
        if ($mode) {
            return chmod($path, $mode);
        }
        return substr(sprintf('%o', fileperms($path)), -4);
    }
    public function delete($paths)
    {
        $paths = is_array($paths) ? $paths : func_get_args();
        $success = true;
        foreach ($paths as $path) {
            try {
                if (@unlink($path)) {
                    clearstatcache(false, $path);
                } else {
                    $success = false;
                }
            } catch (ErrorException) {
                $success = false;
            }
        }
        return $success;
    }
    public function move($path, $target)
    {
        return rename($path, $target);
    }
    public function copy($path, $target)
    {
        return copy($path, $target);
    }
    public function link($target, $link)
    {
        if (!windows_os()) {
            return symlink($target, $link);
        }
        $mode = $this->isDirectory($target) ? 'J' : 'H';
        exec("mklink /{$mode} " . escapeshellarg($link) . ' ' . escapeshellarg($target));
    }
    public function relativeLink($target, $link)
    {
        if (!class_exists(SymfonyFilesystem::class)) {
            throw new RuntimeException('To enable support for relative links, please install the symfony/filesystem package.');
        }
        $relativeTarget = (new SymfonyFilesystem())->makePathRelative($target, dirname($link));
        $this->link($this->isFile($target) ? rtrim($relativeTarget, '/') : $relativeTarget, $link);
    }
    public function name($path)
    {
        return pathinfo($path, PATHINFO_FILENAME);
    }
    public function basename($path)
    {
        return pathinfo($path, PATHINFO_BASENAME);
    }
    public function dirname($path)
    {
        return pathinfo($path, PATHINFO_DIRNAME);
    }
    public function extension($path)
    {
        return pathinfo($path, PATHINFO_EXTENSION);
    }
    public function guessExtension($path)
    {
        if (!class_exists(MimeTypes::class)) {
            throw new RuntimeException('To enable support for guessing extensions, please install the symfony/mime package.');
        }
        return (new MimeTypes())->getExtensions($this->mimeType($path))[0] ?? null;
    }
    public function type($path)
    {
        return filetype($path);
    }
    public function mimeType($path)
    {
        return finfo_file(finfo_open(FILEINFO_MIME_TYPE), $path);
    }
    public function size($path)
    {
        return filesize($path);
    }
    public function lastModified($path)
    {
        return filemtime($path);
    }
    public function isDirectory($directory)
    {
        return is_dir($directory);
    }
    public function isEmptyDirectory($directory, $ignoreDotFiles = false)
    {
        return !Finder::create()->ignoreDotFiles($ignoreDotFiles)->in($directory)->depth(0)->hasResults();
    }
    public function isReadable($path)
    {
        return is_readable($path);
    }
    public function isWritable($path)
    {
        return is_writable($path);
    }
    public function hasSameHash($firstFile, $secondFile)
    {
        $hash = @md5_file($firstFile);
        return $hash && hash_equals($hash, (string) @md5_file($secondFile));
    }
    public function isFile($file)
    {
        return is_file($file);
    }
    public function glob($pattern, $flags = 0)
    {
        return glob($pattern, $flags);
    }
    public function files($directory, $hidden = false)
    {
        return iterator_to_array(Finder::create()->files()->ignoreDotFiles(!$hidden)->in($directory)->depth(0)->sortByName(), false);
    }
    public function allFiles($directory, $hidden = false)
    {
        return iterator_to_array(Finder::create()->files()->ignoreDotFiles(!$hidden)->in($directory)->sortByName(), false);
    }
    public function directories($directory)
    {
        $directories = [];
        foreach (Finder::create()->in($directory)->directories()->depth(0)->sortByName() as $dir) {
            $directories[] = $dir->getPathname();
        }
        return $directories;
    }
    public function ensureDirectoryExists($path, $mode = 0755, $recursive = true)
    {
        if (!$this->isDirectory($path)) {
            $this->makeDirectory($path, $mode, $recursive);
        }
    }
    public function makeDirectory($path, $mode = 0755, $recursive = false, $force = false)
    {
        if ($force) {
            return @mkdir($path, $mode, $recursive);
        }
        return mkdir($path, $mode, $recursive);
    }
    public function moveDirectory($from, $to, $overwrite = false)
    {
        if ($overwrite && $this->isDirectory($to) && !$this->deleteDirectory($to)) {
            return false;
        }
        return @rename($from, $to) === true;
    }
    public function copyDirectory($directory, $destination, $options = null)
    {
        if (!$this->isDirectory($directory)) {
            return false;
        }
        $options = $options ?: FilesystemIterator::SKIP_DOTS;
        $this->ensureDirectoryExists($destination, 0777);
        $items = new FilesystemIterator($directory, $options);
        foreach ($items as $item) {
            $target = $destination . '/' . $item->getBasename();
            if ($item->isDir()) {
                $path = $item->getPathname();
                if (!$this->copyDirectory($path, $target, $options)) {
                    return false;
                }
            } elseif (!$this->copy($item->getPathname(), $target)) {
                return false;
            }
        }
        return true;
    }
    public function deleteDirectory($directory, $preserve = false)
    {
        if (!$this->isDirectory($directory)) {
            return false;
        }
        $items = new FilesystemIterator($directory);
        foreach ($items as $item) {
            if ($item->isDir() && !$item->isLink()) {
                $this->deleteDirectory($item->getPathname());
            } else {
                $this->delete($item->getPathname());
            }
        }
        unset($items);
        if (!$preserve) {
            @rmdir($directory);
        }
        return true;
    }
    public function deleteDirectories($directory)
    {
        $allDirectories = $this->directories($directory);
        if (!empty($allDirectories)) {
            foreach ($allDirectories as $directoryName) {
                $this->deleteDirectory($directoryName);
            }
            return true;
        }
        return false;
    }
    public function cleanDirectory($directory)
    {
        return $this->deleteDirectory($directory, true);
    }
}
}

namespace Illuminate\Filesystem {
use Illuminate\Support\ServiceProvider;
class FilesystemServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->registerNativeFilesystem();
        $this->registerFlysystem();
    }
    protected function registerNativeFilesystem()
    {
        $this->app->singleton('files', function () {
            return new Filesystem();
        });
    }
    protected function registerFlysystem()
    {
        $this->registerManager();
        $this->app->singleton('filesystem.disk', function ($app) {
            return $app['filesystem']->disk($this->getDefaultDriver());
        });
        $this->app->singleton('filesystem.cloud', function ($app) {
            return $app['filesystem']->disk($this->getCloudDriver());
        });
    }
    protected function registerManager()
    {
        $this->app->singleton('filesystem', function ($app) {
            return new FilesystemManager($app);
        });
    }
    protected function getDefaultDriver()
    {
        return $this->app['config']['filesystems.default'];
    }
    protected function getCloudDriver()
    {
        return $this->app['config']['filesystems.cloud'];
    }
}
}

namespace Illuminate\Pipeline {
use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Pipeline\Pipeline as PipelineContract;
use Illuminate\Support\Traits\Conditionable;
use RuntimeException;
use Throwable;
class Pipeline implements PipelineContract
{
    use Conditionable;
    protected $container;
    protected $passable;
    protected $pipes = [];
    protected $method = 'handle';
    public function __construct(?Container $container = null)
    {
        $this->container = $container;
    }
    public function send($passable)
    {
        $this->passable = $passable;
        return $this;
    }
    public function through($pipes)
    {
        $this->pipes = is_array($pipes) ? $pipes : func_get_args();
        return $this;
    }
    public function pipe($pipes)
    {
        array_push($this->pipes, ...is_array($pipes) ? $pipes : func_get_args());
        return $this;
    }
    public function via($method)
    {
        $this->method = $method;
        return $this;
    }
    public function then(Closure $destination)
    {
        $pipeline = array_reduce(array_reverse($this->pipes()), $this->carry(), $this->prepareDestination($destination));
        return $pipeline($this->passable);
    }
    public function thenReturn()
    {
        return $this->then(function ($passable) {
            return $passable;
        });
    }
    protected function prepareDestination(Closure $destination)
    {
        return function ($passable) use ($destination) {
            try {
                return $destination($passable);
            } catch (Throwable $e) {
                return $this->handleException($passable, $e);
            }
        };
    }
    protected function carry()
    {
        return function ($stack, $pipe) {
            return function ($passable) use ($stack, $pipe) {
                try {
                    if (is_callable($pipe)) {
                        return $pipe($passable, $stack);
                    } elseif (!is_object($pipe)) {
                        [$name, $parameters] = $this->parsePipeString($pipe);
                        $pipe = $this->getContainer()->make($name);
                        $parameters = array_merge([$passable, $stack], $parameters);
                    } else {
                        $parameters = [$passable, $stack];
                    }
                    $carry = method_exists($pipe, $this->method) ? $pipe->{$this->method}(...$parameters) : $pipe(...$parameters);
                    return $this->handleCarry($carry);
                } catch (Throwable $e) {
                    return $this->handleException($passable, $e);
                }
            };
        };
    }
    protected function parsePipeString($pipe)
    {
        [$name, $parameters] = array_pad(explode(':', $pipe, 2), 2, []);
        if (is_string($parameters)) {
            $parameters = explode(',', $parameters);
        }
        return [$name, $parameters];
    }
    protected function pipes()
    {
        return $this->pipes;
    }
    protected function getContainer()
    {
        if (!$this->container) {
            throw new RuntimeException('A container instance has not been passed to the Pipeline.');
        }
        return $this->container;
    }
    public function setContainer(Container $container)
    {
        $this->container = $container;
        return $this;
    }
    protected function handleCarry($carry)
    {
        return $carry;
    }
    protected function handleException($passable, Throwable $e)
    {
        throw $e;
    }
}
}

namespace Illuminate\Database {
use Carbon\CarbonInterval;
use Closure;
use DateTimeInterface;
use Doctrine\DBAL\Connection as DoctrineConnection;
use Doctrine\DBAL\Types\Type;
use Exception;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\StatementPrepared;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Query\Grammars\Grammar as QueryGrammar;
use Illuminate\Database\Query\Processors\Processor;
use Illuminate\Database\Schema\Builder as SchemaBuilder;
use Illuminate\Support\Arr;
use Illuminate\Support\InteractsWithTime;
use Illuminate\Support\Traits\Macroable;
use PDO;
use PDOStatement;
use RuntimeException;
class Connection implements ConnectionInterface
{
    use DetectsConcurrencyErrors, DetectsLostConnections, Concerns\ManagesTransactions, InteractsWithTime, Macroable;
    protected $pdo;
    protected $readPdo;
    protected $database;
    protected $readWriteType;
    protected $tablePrefix = '';
    protected $config = [];
    protected $reconnector;
    protected $queryGrammar;
    protected $schemaGrammar;
    protected $postProcessor;
    protected $events;
    protected $fetchMode = PDO::FETCH_OBJ;
    protected $transactions = 0;
    protected $transactionsManager;
    protected $recordsModified = false;
    protected $readOnWriteConnection = false;
    protected $queryLog = [];
    protected $loggingQueries = false;
    protected $totalQueryDuration = 0.0;
    protected $queryDurationHandlers = [];
    protected $pretending = false;
    protected $beforeStartingTransaction = [];
    protected $beforeExecutingCallbacks = [];
    protected $doctrineConnection;
    protected $doctrineTypeMappings = [];
    protected static $resolvers = [];
    public function __construct($pdo, $database = '', $tablePrefix = '', array $config = [])
    {
        $this->pdo = $pdo;
        $this->database = $database;
        $this->tablePrefix = $tablePrefix;
        $this->config = $config;
        $this->useDefaultQueryGrammar();
        $this->useDefaultPostProcessor();
    }
    public function useDefaultQueryGrammar()
    {
        $this->queryGrammar = $this->getDefaultQueryGrammar();
    }
    protected function getDefaultQueryGrammar()
    {
        ($grammar = new QueryGrammar())->setConnection($this);
        return $grammar;
    }
    public function useDefaultSchemaGrammar()
    {
        $this->schemaGrammar = $this->getDefaultSchemaGrammar();
    }
    protected function getDefaultSchemaGrammar()
    {
    }
    public function useDefaultPostProcessor()
    {
        $this->postProcessor = $this->getDefaultPostProcessor();
    }
    protected function getDefaultPostProcessor()
    {
        return new Processor();
    }
    public function getSchemaBuilder()
    {
        if (is_null($this->schemaGrammar)) {
            $this->useDefaultSchemaGrammar();
        }
        return new SchemaBuilder($this);
    }
    public function table($table, $as = null)
    {
        return $this->query()->from($table, $as);
    }
    public function query()
    {
        return new QueryBuilder($this, $this->getQueryGrammar(), $this->getPostProcessor());
    }
    public function selectOne($query, $bindings = [], $useReadPdo = true)
    {
        $records = $this->select($query, $bindings, $useReadPdo);
        return array_shift($records);
    }
    public function scalar($query, $bindings = [], $useReadPdo = true)
    {
        $record = $this->selectOne($query, $bindings, $useReadPdo);
        if (is_null($record)) {
            return null;
        }
        $record = (array) $record;
        if (count($record) > 1) {
            throw new MultipleColumnsSelectedException();
        }
        return reset($record);
    }
    public function selectFromWriteConnection($query, $bindings = [])
    {
        return $this->select($query, $bindings, false);
    }
    public function select($query, $bindings = [], $useReadPdo = true)
    {
        return $this->run($query, $bindings, function ($query, $bindings) use ($useReadPdo) {
            if ($this->pretending()) {
                return [];
            }
            $statement = $this->prepared($this->getPdoForSelect($useReadPdo)->prepare($query));
            $this->bindValues($statement, $this->prepareBindings($bindings));
            $statement->execute();
            return $statement->fetchAll();
        });
    }
    public function selectResultSets($query, $bindings = [], $useReadPdo = true)
    {
        return $this->run($query, $bindings, function ($query, $bindings) use ($useReadPdo) {
            if ($this->pretending()) {
                return [];
            }
            $statement = $this->prepared($this->getPdoForSelect($useReadPdo)->prepare($query));
            $this->bindValues($statement, $this->prepareBindings($bindings));
            $statement->execute();
            $sets = [];
            do {
                $sets[] = $statement->fetchAll();
            } while ($statement->nextRowset());
            return $sets;
        });
    }
    public function cursor($query, $bindings = [], $useReadPdo = true)
    {
        $statement = $this->run($query, $bindings, function ($query, $bindings) use ($useReadPdo) {
            if ($this->pretending()) {
                return [];
            }
            $statement = $this->prepared($this->getPdoForSelect($useReadPdo)->prepare($query));
            $this->bindValues($statement, $this->prepareBindings($bindings));
            $statement->execute();
            return $statement;
        });
        while ($record = $statement->fetch()) {
            yield $record;
        }
    }
    protected function prepared(PDOStatement $statement)
    {
        $statement->setFetchMode($this->fetchMode);
        $this->event(new StatementPrepared($this, $statement));
        return $statement;
    }
    protected function getPdoForSelect($useReadPdo = true)
    {
        return $useReadPdo ? $this->getReadPdo() : $this->getPdo();
    }
    public function insert($query, $bindings = [])
    {
        return $this->statement($query, $bindings);
    }
    public function update($query, $bindings = [])
    {
        return $this->affectingStatement($query, $bindings);
    }
    public function delete($query, $bindings = [])
    {
        return $this->affectingStatement($query, $bindings);
    }
    public function statement($query, $bindings = [])
    {
        return $this->run($query, $bindings, function ($query, $bindings) {
            if ($this->pretending()) {
                return true;
            }
            $statement = $this->getPdo()->prepare($query);
            $this->bindValues($statement, $this->prepareBindings($bindings));
            $this->recordsHaveBeenModified();
            return $statement->execute();
        });
    }
    public function affectingStatement($query, $bindings = [])
    {
        return $this->run($query, $bindings, function ($query, $bindings) {
            if ($this->pretending()) {
                return 0;
            }
            $statement = $this->getPdo()->prepare($query);
            $this->bindValues($statement, $this->prepareBindings($bindings));
            $statement->execute();
            $this->recordsHaveBeenModified(($count = $statement->rowCount()) > 0);
            return $count;
        });
    }
    public function unprepared($query)
    {
        return $this->run($query, [], function ($query) {
            if ($this->pretending()) {
                return true;
            }
            $this->recordsHaveBeenModified($change = $this->getPdo()->exec($query) !== false);
            return $change;
        });
    }
    public function pretend(Closure $callback)
    {
        return $this->withFreshQueryLog(function () use ($callback) {
            $this->pretending = true;
            $callback($this);
            $this->pretending = false;
            return $this->queryLog;
        });
    }
    public function withoutPretending(Closure $callback)
    {
        if (!$this->pretending) {
            return $callback();
        }
        $this->pretending = false;
        $result = $callback();
        $this->pretending = true;
        return $result;
    }
    protected function withFreshQueryLog($callback)
    {
        $loggingQueries = $this->loggingQueries;
        $this->enableQueryLog();
        $this->queryLog = [];
        $result = $callback();
        $this->loggingQueries = $loggingQueries;
        return $result;
    }
    public function bindValues($statement, $bindings)
    {
        foreach ($bindings as $key => $value) {
            $statement->bindValue(is_string($key) ? $key : $key + 1, $value, match (true) {
                is_int($value) => PDO::PARAM_INT,
                is_resource($value) => PDO::PARAM_LOB,
                default => PDO::PARAM_STR,
            });
        }
    }
    public function prepareBindings(array $bindings)
    {
        $grammar = $this->getQueryGrammar();
        foreach ($bindings as $key => $value) {
            if ($value instanceof DateTimeInterface) {
                $bindings[$key] = $value->format($grammar->getDateFormat());
            } elseif (is_bool($value)) {
                $bindings[$key] = (int) $value;
            }
        }
        return $bindings;
    }
    protected function run($query, $bindings, Closure $callback)
    {
        foreach ($this->beforeExecutingCallbacks as $beforeExecutingCallback) {
            $beforeExecutingCallback($query, $bindings, $this);
        }
        $this->reconnectIfMissingConnection();
        $start = microtime(true);
        try {
            $result = $this->runQueryCallback($query, $bindings, $callback);
        } catch (QueryException $e) {
            $result = $this->handleQueryException($e, $query, $bindings, $callback);
        }
        $this->logQuery($query, $bindings, $this->getElapsedTime($start));
        return $result;
    }
    protected function runQueryCallback($query, $bindings, Closure $callback)
    {
        try {
            return $callback($query, $bindings);
        } catch (Exception $e) {
            if ($this->isUniqueConstraintError($e)) {
                throw new UniqueConstraintViolationException($this->getName(), $query, $this->prepareBindings($bindings), $e);
            }
            throw new QueryException($this->getName(), $query, $this->prepareBindings($bindings), $e);
        }
    }
    protected function isUniqueConstraintError(Exception $exception)
    {
        return false;
    }
    public function logQuery($query, $bindings, $time = null)
    {
        $this->totalQueryDuration += $time ?? 0.0;
        $this->event(new QueryExecuted($query, $bindings, $time, $this));
        $query = $this->pretending === true ? $this->queryGrammar?->substituteBindingsIntoRawSql($query, $bindings) ?? $query : $query;
        if ($this->loggingQueries) {
            $this->queryLog[] = compact('query', 'bindings', 'time');
        }
    }
    protected function getElapsedTime($start)
    {
        return round((microtime(true) - $start) * 1000, 2);
    }
    public function whenQueryingForLongerThan($threshold, $handler)
    {
        $threshold = $threshold instanceof DateTimeInterface ? $this->secondsUntil($threshold) * 1000 : $threshold;
        $threshold = $threshold instanceof CarbonInterval ? $threshold->totalMilliseconds : $threshold;
        $this->queryDurationHandlers[] = ['has_run' => false, 'handler' => $handler];
        $key = count($this->queryDurationHandlers) - 1;
        $this->listen(function ($event) use ($threshold, $handler, $key) {
            if (!$this->queryDurationHandlers[$key]['has_run'] && $this->totalQueryDuration() > $threshold) {
                $handler($this, $event);
                $this->queryDurationHandlers[$key]['has_run'] = true;
            }
        });
    }
    public function allowQueryDurationHandlersToRunAgain()
    {
        foreach ($this->queryDurationHandlers as $key => $queryDurationHandler) {
            $this->queryDurationHandlers[$key]['has_run'] = false;
        }
    }
    public function totalQueryDuration()
    {
        return $this->totalQueryDuration;
    }
    public function resetTotalQueryDuration()
    {
        $this->totalQueryDuration = 0.0;
    }
    protected function handleQueryException(QueryException $e, $query, $bindings, Closure $callback)
    {
        if ($this->transactions >= 1) {
            throw $e;
        }
        return $this->tryAgainIfCausedByLostConnection($e, $query, $bindings, $callback);
    }
    protected function tryAgainIfCausedByLostConnection(QueryException $e, $query, $bindings, Closure $callback)
    {
        if ($this->causedByLostConnection($e->getPrevious())) {
            $this->reconnect();
            return $this->runQueryCallback($query, $bindings, $callback);
        }
        throw $e;
    }
    public function reconnect()
    {
        if (is_callable($this->reconnector)) {
            $this->doctrineConnection = null;
            return call_user_func($this->reconnector, $this);
        }
        throw new LostConnectionException('Lost connection and no reconnector available.');
    }
    public function reconnectIfMissingConnection()
    {
        if (is_null($this->pdo)) {
            $this->reconnect();
        }
    }
    public function disconnect()
    {
        $this->setPdo(null)->setReadPdo(null);
        $this->doctrineConnection = null;
    }
    public function beforeStartingTransaction(Closure $callback)
    {
        $this->beforeStartingTransaction[] = $callback;
        return $this;
    }
    public function beforeExecuting(Closure $callback)
    {
        $this->beforeExecutingCallbacks[] = $callback;
        return $this;
    }
    public function listen(Closure $callback)
    {
        $this->events?->listen(Events\QueryExecuted::class, $callback);
    }
    protected function fireConnectionEvent($event)
    {
        return $this->events?->dispatch(match ($event) {
            'beganTransaction' => new TransactionBeginning($this),
            'committed' => new TransactionCommitted($this),
            'committing' => new TransactionCommitting($this),
            'rollingBack' => new TransactionRolledBack($this),
            default => null,
        });
    }
    protected function event($event)
    {
        $this->events?->dispatch($event);
    }
    public function raw($value)
    {
        return new Expression($value);
    }
    public function escape($value, $binary = false)
    {
        if ($value === null) {
            return 'null';
        } elseif ($binary) {
            return $this->escapeBinary($value);
        } elseif (is_int($value) || is_float($value)) {
            return (string) $value;
        } elseif (is_bool($value)) {
            return $this->escapeBool($value);
        } elseif (is_array($value)) {
            throw new RuntimeException('The database connection does not support escaping arrays.');
        } else {
            if (str_contains($value, "\x00")) {
                throw new RuntimeException('Strings with null bytes cannot be escaped. Use the binary escape option.');
            }
            if (preg_match('//u', $value) === false) {
                throw new RuntimeException('Strings with invalid UTF-8 byte sequences cannot be escaped.');
            }
            return $this->escapeString($value);
        }
    }
    protected function escapeString($value)
    {
        return $this->getReadPdo()->quote($value);
    }
    protected function escapeBool($value)
    {
        return $value ? '1' : '0';
    }
    protected function escapeBinary($value)
    {
        throw new RuntimeException('The database connection does not support escaping binary values.');
    }
    public function hasModifiedRecords()
    {
        return $this->recordsModified;
    }
    public function recordsHaveBeenModified($value = true)
    {
        if (!$this->recordsModified) {
            $this->recordsModified = $value;
        }
    }
    public function setRecordModificationState(bool $value)
    {
        $this->recordsModified = $value;
        return $this;
    }
    public function forgetRecordModificationState()
    {
        $this->recordsModified = false;
    }
    public function useWriteConnectionWhenReading($value = true)
    {
        $this->readOnWriteConnection = $value;
        return $this;
    }
    public function isDoctrineAvailable()
    {
        return class_exists('Doctrine\DBAL\Connection');
    }
    public function usingNativeSchemaOperations()
    {
        return !$this->isDoctrineAvailable() || SchemaBuilder::$alwaysUsesNativeSchemaOperationsIfPossible;
    }
    public function getDoctrineColumn($table, $column)
    {
        $schema = $this->getDoctrineSchemaManager();
        return $schema->introspectTable($table)->getColumn($column);
    }
    public function getDoctrineSchemaManager()
    {
        $connection = $this->getDoctrineConnection();
        return $connection->createSchemaManager();
    }
    public function getDoctrineConnection()
    {
        if (is_null($this->doctrineConnection)) {
            $driver = $this->getDoctrineDriver();
            $this->doctrineConnection = new DoctrineConnection(array_filter(['pdo' => $this->getPdo(), 'dbname' => $this->getDatabaseName(), 'driver' => $driver->getName(), 'serverVersion' => $this->getConfig('server_version')]), $driver);
            foreach ($this->doctrineTypeMappings as $name => $type) {
                $this->doctrineConnection->getDatabasePlatform()->registerDoctrineTypeMapping($type, $name);
            }
        }
        return $this->doctrineConnection;
    }
    public function registerDoctrineType(Type|string $class, string $name, string $type): void
    {
        if (!$this->isDoctrineAvailable()) {
            throw new RuntimeException('Registering a custom Doctrine type requires Doctrine DBAL (doctrine/dbal).');
        }
        if (!Type::hasType($name)) {
            Type::getTypeRegistry()->register($name, is_string($class) ? new $class() : $class);
        }
        $this->doctrineTypeMappings[$name] = $type;
    }
    public function getPdo()
    {
        if ($this->pdo instanceof Closure) {
            return $this->pdo = call_user_func($this->pdo);
        }
        return $this->pdo;
    }
    public function getRawPdo()
    {
        return $this->pdo;
    }
    public function getReadPdo()
    {
        if ($this->transactions > 0) {
            return $this->getPdo();
        }
        if ($this->readOnWriteConnection || $this->recordsModified && $this->getConfig('sticky')) {
            return $this->getPdo();
        }
        if ($this->readPdo instanceof Closure) {
            return $this->readPdo = call_user_func($this->readPdo);
        }
        return $this->readPdo ?: $this->getPdo();
    }
    public function getRawReadPdo()
    {
        return $this->readPdo;
    }
    public function setPdo($pdo)
    {
        $this->transactions = 0;
        $this->pdo = $pdo;
        return $this;
    }
    public function setReadPdo($pdo)
    {
        $this->readPdo = $pdo;
        return $this;
    }
    public function setReconnector(callable $reconnector)
    {
        $this->reconnector = $reconnector;
        return $this;
    }
    public function getName()
    {
        return $this->getConfig('name');
    }
    public function getNameWithReadWriteType()
    {
        return $this->getName() . ($this->readWriteType ? '::' . $this->readWriteType : '');
    }
    public function getConfig($option = null)
    {
        return Arr::get($this->config, $option);
    }
    public function getDriverName()
    {
        return $this->getConfig('driver');
    }
    public function getQueryGrammar()
    {
        return $this->queryGrammar;
    }
    public function setQueryGrammar(Query\Grammars\Grammar $grammar)
    {
        $this->queryGrammar = $grammar;
        return $this;
    }
    public function getSchemaGrammar()
    {
        return $this->schemaGrammar;
    }
    public function setSchemaGrammar(Schema\Grammars\Grammar $grammar)
    {
        $this->schemaGrammar = $grammar;
        return $this;
    }
    public function getPostProcessor()
    {
        return $this->postProcessor;
    }
    public function setPostProcessor(Processor $processor)
    {
        $this->postProcessor = $processor;
        return $this;
    }
    public function getEventDispatcher()
    {
        return $this->events;
    }
    public function setEventDispatcher(Dispatcher $events)
    {
        $this->events = $events;
        return $this;
    }
    public function unsetEventDispatcher()
    {
        $this->events = null;
    }
    public function setTransactionManager($manager)
    {
        $this->transactionsManager = $manager;
        return $this;
    }
    public function unsetTransactionManager()
    {
        $this->transactionsManager = null;
    }
    public function pretending()
    {
        return $this->pretending === true;
    }
    public function getQueryLog()
    {
        return $this->queryLog;
    }
    public function getRawQueryLog()
    {
        return array_map(fn(array $log) => ['raw_query' => $this->queryGrammar->substituteBindingsIntoRawSql($log['query'], $this->prepareBindings($log['bindings'])), 'time' => $log['time']], $this->getQueryLog());
    }
    public function flushQueryLog()
    {
        $this->queryLog = [];
    }
    public function enableQueryLog()
    {
        $this->loggingQueries = true;
    }
    public function disableQueryLog()
    {
        $this->loggingQueries = false;
    }
    public function logging()
    {
        return $this->loggingQueries;
    }
    public function getDatabaseName()
    {
        return $this->database;
    }
    public function setDatabaseName($database)
    {
        $this->database = $database;
        return $this;
    }
    public function setReadWriteType($readWriteType)
    {
        $this->readWriteType = $readWriteType;
        return $this;
    }
    public function getTablePrefix()
    {
        return $this->tablePrefix;
    }
    public function setTablePrefix($prefix)
    {
        $this->tablePrefix = $prefix;
        $this->getQueryGrammar()->setTablePrefix($prefix);
        return $this;
    }
    public function withTablePrefix(Grammar $grammar)
    {
        $grammar->setTablePrefix($this->tablePrefix);
        return $grammar;
    }
    public static function resolverFor($driver, Closure $callback)
    {
        static::$resolvers[$driver] = $callback;
    }
    public static function getResolver($driver)
    {
        return static::$resolvers[$driver] ?? null;
    }
}
}

namespace Illuminate\Database {
use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Support\Traits\Macroable;
use RuntimeException;
abstract class Grammar
{
    use Macroable;
    protected $connection;
    protected $tablePrefix = '';
    public function wrapArray(array $values)
    {
        return array_map([$this, 'wrap'], $values);
    }
    public function wrapTable($table)
    {
        if (!$this->isExpression($table)) {
            return $this->wrap($this->tablePrefix . $table, true);
        }
        return $this->getValue($table);
    }
    public function wrap($value, $prefixAlias = false)
    {
        if ($this->isExpression($value)) {
            return $this->getValue($value);
        }
        if (stripos($value, ' as ') !== false) {
            return $this->wrapAliasedValue($value, $prefixAlias);
        }
        if ($this->isJsonSelector($value)) {
            return $this->wrapJsonSelector($value);
        }
        return $this->wrapSegments(explode('.', $value));
    }
    protected function wrapAliasedValue($value, $prefixAlias = false)
    {
        $segments = preg_split('/\s+as\s+/i', $value);
        if ($prefixAlias) {
            $segments[1] = $this->tablePrefix . $segments[1];
        }
        return $this->wrap($segments[0]) . ' as ' . $this->wrapValue($segments[1]);
    }
    protected function wrapSegments($segments)
    {
        return collect($segments)->map(function ($segment, $key) use ($segments) {
            return $key == 0 && count($segments) > 1 ? $this->wrapTable($segment) : $this->wrapValue($segment);
        })->implode('.');
    }
    protected function wrapValue($value)
    {
        if ($value !== '*') {
            return '"' . str_replace('"', '""', $value) . '"';
        }
        return $value;
    }
    protected function wrapJsonSelector($value)
    {
        throw new RuntimeException('This database engine does not support JSON operations.');
    }
    protected function isJsonSelector($value)
    {
        return str_contains($value, '->');
    }
    public function columnize(array $columns)
    {
        return implode(', ', array_map([$this, 'wrap'], $columns));
    }
    public function parameterize(array $values)
    {
        return implode(', ', array_map([$this, 'parameter'], $values));
    }
    public function parameter($value)
    {
        return $this->isExpression($value) ? $this->getValue($value) : '?';
    }
    public function quoteString($value)
    {
        if (is_array($value)) {
            return implode(', ', array_map([$this, __FUNCTION__], $value));
        }
        return "'{$value}'";
    }
    public function escape($value, $binary = false)
    {
        if (is_null($this->connection)) {
            throw new RuntimeException("The database driver's grammar implementation does not support escaping values.");
        }
        return $this->connection->escape($value, $binary);
    }
    public function isExpression($value)
    {
        return $value instanceof Expression;
    }
    public function getValue($expression)
    {
        if ($this->isExpression($expression)) {
            return $this->getValue($expression->getValue($this));
        }
        return $expression;
    }
    public function getDateFormat()
    {
        return 'Y-m-d H:i:s';
    }
    public function getTablePrefix()
    {
        return $this->tablePrefix;
    }
    public function setTablePrefix($prefix)
    {
        $this->tablePrefix = $prefix;
        return $this;
    }
    public function setConnection($connection)
    {
        $this->connection = $connection;
        return $this;
    }
}
}

namespace Illuminate\Database {
use Doctrine\DBAL\Types\Type;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Database\Events\ConnectionEstablished;
use Illuminate\Support\Arr;
use Illuminate\Support\ConfigurationUrlParser;
use Illuminate\Support\Str;
use Illuminate\Support\Traits\Macroable;
use InvalidArgumentException;
use PDO;
use RuntimeException;
class DatabaseManager implements ConnectionResolverInterface
{
    use Macroable {
        __call as macroCall;
    }
    protected $app;
    protected $factory;
    protected $connections = [];
    protected $extensions = [];
    protected $reconnector;
    protected $doctrineTypes = [];
    public function __construct($app, ConnectionFactory $factory)
    {
        $this->app = $app;
        $this->factory = $factory;
        $this->reconnector = function ($connection) {
            $this->reconnect($connection->getNameWithReadWriteType());
        };
    }
    public function connection($name = null)
    {
        [$database, $type] = $this->parseConnectionName($name);
        $name = $name ?: $database;
        if (!isset($this->connections[$name])) {
            $this->connections[$name] = $this->configure($this->makeConnection($database), $type);
            $this->dispatchConnectionEstablishedEvent($this->connections[$name]);
        }
        return $this->connections[$name];
    }
    public function connectUsing(string $name, array $config, bool $force = false)
    {
        if ($force) {
            $this->purge($name);
        }
        if (isset($this->connections[$name])) {
            throw new RuntimeException("Cannot establish connection [{$name}] because another connection with that name already exists.");
        }
        $connection = $this->configure($this->factory->make($config, $name), null);
        $this->dispatchConnectionEstablishedEvent($connection);
        return tap($connection, fn($connection) => $this->connections[$name] = $connection);
    }
    protected function parseConnectionName($name)
    {
        $name = $name ?: $this->getDefaultConnection();
        return Str::endsWith($name, ['::read', '::write']) ? explode('::', $name, 2) : [$name, null];
    }
    protected function makeConnection($name)
    {
        $config = $this->configuration($name);
        if (isset($this->extensions[$name])) {
            return call_user_func($this->extensions[$name], $config, $name);
        }
        if (isset($this->extensions[$driver = $config['driver']])) {
            return call_user_func($this->extensions[$driver], $config, $name);
        }
        return $this->factory->make($config, $name);
    }
    protected function configuration($name)
    {
        $name = $name ?: $this->getDefaultConnection();
        $connections = $this->app['config']['database.connections'];
        if (is_null($config = Arr::get($connections, $name))) {
            throw new InvalidArgumentException("Database connection [{$name}] not configured.");
        }
        return (new ConfigurationUrlParser())->parseConfiguration($config);
    }
    protected function configure(Connection $connection, $type)
    {
        $connection = $this->setPdoForType($connection, $type)->setReadWriteType($type);
        if ($this->app->bound('events')) {
            $connection->setEventDispatcher($this->app['events']);
        }
        if ($this->app->bound('db.transactions')) {
            $connection->setTransactionManager($this->app['db.transactions']);
        }
        $connection->setReconnector($this->reconnector);
        $this->registerConfiguredDoctrineTypes($connection);
        return $connection;
    }
    protected function dispatchConnectionEstablishedEvent(Connection $connection)
    {
        if (!$this->app->bound('events')) {
            return;
        }
        $this->app['events']->dispatch(new ConnectionEstablished($connection));
    }
    protected function setPdoForType(Connection $connection, $type = null)
    {
        if ($type === 'read') {
            $connection->setPdo($connection->getReadPdo());
        } elseif ($type === 'write') {
            $connection->setReadPdo($connection->getPdo());
        }
        return $connection;
    }
    protected function registerConfiguredDoctrineTypes(Connection $connection): void
    {
        foreach ($this->app['config']->get('database.dbal.types', []) as $name => $class) {
            $this->registerDoctrineType($class, $name, $name);
        }
        foreach ($this->doctrineTypes as $name => [$type, $class]) {
            $connection->registerDoctrineType($class, $name, $type);
        }
    }
    public function registerDoctrineType(string $class, string $name, string $type): void
    {
        if (!class_exists('Doctrine\DBAL\Connection')) {
            throw new RuntimeException('Registering a custom Doctrine type requires Doctrine DBAL (doctrine/dbal).');
        }
        if (!Type::hasType($name)) {
            Type::addType($name, $class);
        }
        $this->doctrineTypes[$name] = [$type, $class];
    }
    public function purge($name = null)
    {
        $name = $name ?: $this->getDefaultConnection();
        $this->disconnect($name);
        unset($this->connections[$name]);
    }
    public function disconnect($name = null)
    {
        if (isset($this->connections[$name = $name ?: $this->getDefaultConnection()])) {
            $this->connections[$name]->disconnect();
        }
    }
    public function reconnect($name = null)
    {
        $this->disconnect($name = $name ?: $this->getDefaultConnection());
        if (!isset($this->connections[$name])) {
            return $this->connection($name);
        }
        return $this->refreshPdoConnections($name);
    }
    public function usingConnection($name, callable $callback)
    {
        $previousName = $this->getDefaultConnection();
        $this->setDefaultConnection($name);
        return tap($callback(), function () use ($previousName) {
            $this->setDefaultConnection($previousName);
        });
    }
    protected function refreshPdoConnections($name)
    {
        [$database, $type] = $this->parseConnectionName($name);
        $fresh = $this->configure($this->makeConnection($database), $type);
        return $this->connections[$name]->setPdo($fresh->getRawPdo())->setReadPdo($fresh->getRawReadPdo());
    }
    public function getDefaultConnection()
    {
        return $this->app['config']['database.default'];
    }
    public function setDefaultConnection($name)
    {
        $this->app['config']['database.default'] = $name;
    }
    public function supportedDrivers()
    {
        return ['mysql', 'pgsql', 'sqlite', 'sqlsrv'];
    }
    public function availableDrivers()
    {
        return array_intersect($this->supportedDrivers(), str_replace('dblib', 'sqlsrv', PDO::getAvailableDrivers()));
    }
    public function extend($name, callable $resolver)
    {
        $this->extensions[$name] = $resolver;
    }
    public function forgetExtension($name)
    {
        unset($this->extensions[$name]);
    }
    public function getConnections()
    {
        return $this->connections;
    }
    public function setReconnector(callable $reconnector)
    {
        $this->reconnector = $reconnector;
    }
    public function setApplication($app)
    {
        $this->app = $app;
        return $this;
    }
    public function __call($method, $parameters)
    {
        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }
        return $this->connection()->{$method}(...$parameters);
    }
}
}

namespace Illuminate\Database {
use Exception;
use Illuminate\Database\PDO\PostgresDriver;
use Illuminate\Database\Query\Grammars\PostgresGrammar as QueryGrammar;
use Illuminate\Database\Query\Processors\PostgresProcessor;
use Illuminate\Database\Schema\Grammars\PostgresGrammar as SchemaGrammar;
use Illuminate\Database\Schema\PostgresBuilder;
use Illuminate\Database\Schema\PostgresSchemaState;
use Illuminate\Filesystem\Filesystem;
class PostgresConnection extends Connection
{
    protected function escapeBinary($value)
    {
        $hex = bin2hex($value);
        return "'\\x{$hex}'::bytea";
    }
    protected function escapeBool($value)
    {
        return $value ? 'true' : 'false';
    }
    protected function isUniqueConstraintError(Exception $exception)
    {
        return '23505' === $exception->getCode();
    }
    protected function getDefaultQueryGrammar()
    {
        ($grammar = new QueryGrammar())->setConnection($this);
        return $this->withTablePrefix($grammar);
    }
    public function getSchemaBuilder()
    {
        if (is_null($this->schemaGrammar)) {
            $this->useDefaultSchemaGrammar();
        }
        return new PostgresBuilder($this);
    }
    protected function getDefaultSchemaGrammar()
    {
        ($grammar = new SchemaGrammar())->setConnection($this);
        return $this->withTablePrefix($grammar);
    }
    public function getSchemaState(?Filesystem $files = null, ?callable $processFactory = null)
    {
        return new PostgresSchemaState($this, $files, $processFactory);
    }
    protected function getDefaultPostProcessor()
    {
        return new PostgresProcessor();
    }
    protected function getDoctrineDriver()
    {
        return new PostgresDriver();
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Concerns\CompilesJsonPaths;
use Illuminate\Database\Grammar as BaseGrammar;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\JoinClause;
use Illuminate\Database\Query\JoinLateralClause;
use Illuminate\Support\Arr;
use RuntimeException;
class Grammar extends BaseGrammar
{
    use CompilesJsonPaths;
    protected $operators = [];
    protected $bitwiseOperators = [];
    protected $selectComponents = ['aggregate', 'columns', 'from', 'indexHint', 'joins', 'wheres', 'groups', 'havings', 'orders', 'limit', 'offset', 'lock'];
    public function compileSelect(Builder $query)
    {
        if (($query->unions || $query->havings) && $query->aggregate) {
            return $this->compileUnionAggregate($query);
        }
        $original = $query->columns;
        if (is_null($query->columns)) {
            $query->columns = ['*'];
        }
        $sql = trim($this->concatenate($this->compileComponents($query)));
        if ($query->unions) {
            $sql = $this->wrapUnion($sql) . ' ' . $this->compileUnions($query);
        }
        $query->columns = $original;
        return $sql;
    }
    protected function compileComponents(Builder $query)
    {
        $sql = [];
        foreach ($this->selectComponents as $component) {
            if (isset($query->{$component})) {
                $method = 'compile' . ucfirst($component);
                $sql[$component] = $this->{$method}($query, $query->{$component});
            }
        }
        return $sql;
    }
    protected function compileAggregate(Builder $query, $aggregate)
    {
        $column = $this->columnize($aggregate['columns']);
        if (is_array($query->distinct)) {
            $column = 'distinct ' . $this->columnize($query->distinct);
        } elseif ($query->distinct && $column !== '*') {
            $column = 'distinct ' . $column;
        }
        return 'select ' . $aggregate['function'] . '(' . $column . ') as aggregate';
    }
    protected function compileColumns(Builder $query, $columns)
    {
        if (!is_null($query->aggregate)) {
            return;
        }
        if ($query->distinct) {
            $select = 'select distinct ';
        } else {
            $select = 'select ';
        }
        return $select . $this->columnize($columns);
    }
    protected function compileFrom(Builder $query, $table)
    {
        return 'from ' . $this->wrapTable($table);
    }
    protected function compileJoins(Builder $query, $joins)
    {
        return collect($joins)->map(function ($join) use ($query) {
            $table = $this->wrapTable($join->table);
            $nestedJoins = is_null($join->joins) ? '' : ' ' . $this->compileJoins($query, $join->joins);
            $tableAndNestedJoins = is_null($join->joins) ? $table : '(' . $table . $nestedJoins . ')';
            if ($join instanceof JoinLateralClause) {
                return $this->compileJoinLateral($join, $tableAndNestedJoins);
            }
            return trim("{$join->type} join {$tableAndNestedJoins} {$this->compileWheres($join)}");
        })->implode(' ');
    }
    public function compileJoinLateral(JoinLateralClause $join, string $expression): string
    {
        throw new RuntimeException('This database engine does not support lateral joins.');
    }
    public function compileWheres(Builder $query)
    {
        if (is_null($query->wheres)) {
            return '';
        }
        if (count($sql = $this->compileWheresToArray($query)) > 0) {
            return $this->concatenateWhereClauses($query, $sql);
        }
        return '';
    }
    protected function compileWheresToArray($query)
    {
        return collect($query->wheres)->map(function ($where) use ($query) {
            return $where['boolean'] . ' ' . $this->{"where{$where['type']}"}($query, $where);
        })->all();
    }
    protected function concatenateWhereClauses($query, $sql)
    {
        $conjunction = $query instanceof JoinClause ? 'on' : 'where';
        return $conjunction . ' ' . $this->removeLeadingBoolean(implode(' ', $sql));
    }
    protected function whereRaw(Builder $query, $where)
    {
        return $where['sql'] instanceof Expression ? $where['sql']->getValue($this) : $where['sql'];
    }
    protected function whereBasic(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        $operator = str_replace('?', '??', $where['operator']);
        return $this->wrap($where['column']) . ' ' . $operator . ' ' . $value;
    }
    protected function whereBitwise(Builder $query, $where)
    {
        return $this->whereBasic($query, $where);
    }
    protected function whereIn(Builder $query, $where)
    {
        if (!empty($where['values'])) {
            return $this->wrap($where['column']) . ' in (' . $this->parameterize($where['values']) . ')';
        }
        return '0 = 1';
    }
    protected function whereNotIn(Builder $query, $where)
    {
        if (!empty($where['values'])) {
            return $this->wrap($where['column']) . ' not in (' . $this->parameterize($where['values']) . ')';
        }
        return '1 = 1';
    }
    protected function whereNotInRaw(Builder $query, $where)
    {
        if (!empty($where['values'])) {
            return $this->wrap($where['column']) . ' not in (' . implode(', ', $where['values']) . ')';
        }
        return '1 = 1';
    }
    protected function whereInRaw(Builder $query, $where)
    {
        if (!empty($where['values'])) {
            return $this->wrap($where['column']) . ' in (' . implode(', ', $where['values']) . ')';
        }
        return '0 = 1';
    }
    protected function whereNull(Builder $query, $where)
    {
        return $this->wrap($where['column']) . ' is null';
    }
    protected function whereNotNull(Builder $query, $where)
    {
        return $this->wrap($where['column']) . ' is not null';
    }
    protected function whereBetween(Builder $query, $where)
    {
        $between = $where['not'] ? 'not between' : 'between';
        $min = $this->parameter(is_array($where['values']) ? reset($where['values']) : $where['values'][0]);
        $max = $this->parameter(is_array($where['values']) ? end($where['values']) : $where['values'][1]);
        return $this->wrap($where['column']) . ' ' . $between . ' ' . $min . ' and ' . $max;
    }
    protected function whereBetweenColumns(Builder $query, $where)
    {
        $between = $where['not'] ? 'not between' : 'between';
        $min = $this->wrap(is_array($where['values']) ? reset($where['values']) : $where['values'][0]);
        $max = $this->wrap(is_array($where['values']) ? end($where['values']) : $where['values'][1]);
        return $this->wrap($where['column']) . ' ' . $between . ' ' . $min . ' and ' . $max;
    }
    protected function whereDate(Builder $query, $where)
    {
        return $this->dateBasedWhere('date', $query, $where);
    }
    protected function whereTime(Builder $query, $where)
    {
        return $this->dateBasedWhere('time', $query, $where);
    }
    protected function whereDay(Builder $query, $where)
    {
        return $this->dateBasedWhere('day', $query, $where);
    }
    protected function whereMonth(Builder $query, $where)
    {
        return $this->dateBasedWhere('month', $query, $where);
    }
    protected function whereYear(Builder $query, $where)
    {
        return $this->dateBasedWhere('year', $query, $where);
    }
    protected function dateBasedWhere($type, Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return $type . '(' . $this->wrap($where['column']) . ') ' . $where['operator'] . ' ' . $value;
    }
    protected function whereColumn(Builder $query, $where)
    {
        return $this->wrap($where['first']) . ' ' . $where['operator'] . ' ' . $this->wrap($where['second']);
    }
    protected function whereNested(Builder $query, $where)
    {
        $offset = $where['query'] instanceof JoinClause ? 3 : 6;
        return '(' . substr($this->compileWheres($where['query']), $offset) . ')';
    }
    protected function whereSub(Builder $query, $where)
    {
        $select = $this->compileSelect($where['query']);
        return $this->wrap($where['column']) . ' ' . $where['operator'] . " ({$select})";
    }
    protected function whereExists(Builder $query, $where)
    {
        return 'exists (' . $this->compileSelect($where['query']) . ')';
    }
    protected function whereNotExists(Builder $query, $where)
    {
        return 'not exists (' . $this->compileSelect($where['query']) . ')';
    }
    protected function whereRowValues(Builder $query, $where)
    {
        $columns = $this->columnize($where['columns']);
        $values = $this->parameterize($where['values']);
        return '(' . $columns . ') ' . $where['operator'] . ' (' . $values . ')';
    }
    protected function whereJsonBoolean(Builder $query, $where)
    {
        $column = $this->wrapJsonBooleanSelector($where['column']);
        $value = $this->wrapJsonBooleanValue($this->parameter($where['value']));
        return $column . ' ' . $where['operator'] . ' ' . $value;
    }
    protected function whereJsonContains(Builder $query, $where)
    {
        $not = $where['not'] ? 'not ' : '';
        return $not . $this->compileJsonContains($where['column'], $this->parameter($where['value']));
    }
    protected function compileJsonContains($column, $value)
    {
        throw new RuntimeException('This database engine does not support JSON contains operations.');
    }
    public function prepareBindingForJsonContains($binding)
    {
        return json_encode($binding, JSON_UNESCAPED_UNICODE);
    }
    protected function whereJsonContainsKey(Builder $query, $where)
    {
        $not = $where['not'] ? 'not ' : '';
        return $not . $this->compileJsonContainsKey($where['column']);
    }
    protected function compileJsonContainsKey($column)
    {
        throw new RuntimeException('This database engine does not support JSON contains key operations.');
    }
    protected function whereJsonLength(Builder $query, $where)
    {
        return $this->compileJsonLength($where['column'], $where['operator'], $this->parameter($where['value']));
    }
    protected function compileJsonLength($column, $operator, $value)
    {
        throw new RuntimeException('This database engine does not support JSON length operations.');
    }
    public function compileJsonValueCast($value)
    {
        return $value;
    }
    public function whereFullText(Builder $query, $where)
    {
        throw new RuntimeException('This database engine does not support fulltext search operations.');
    }
    public function whereExpression(Builder $query, $where)
    {
        return $where['column']->getValue($this);
    }
    protected function compileGroups(Builder $query, $groups)
    {
        return 'group by ' . $this->columnize($groups);
    }
    protected function compileHavings(Builder $query)
    {
        return 'having ' . $this->removeLeadingBoolean(collect($query->havings)->map(function ($having) {
            return $having['boolean'] . ' ' . $this->compileHaving($having);
        })->implode(' '));
    }
    protected function compileHaving(array $having)
    {
        return match ($having['type']) {
            'Raw' => $having['sql'],
            'between' => $this->compileHavingBetween($having),
            'Null' => $this->compileHavingNull($having),
            'NotNull' => $this->compileHavingNotNull($having),
            'bit' => $this->compileHavingBit($having),
            'Expression' => $this->compileHavingExpression($having),
            'Nested' => $this->compileNestedHavings($having),
            default => $this->compileBasicHaving($having),
        };
    }
    protected function compileBasicHaving($having)
    {
        $column = $this->wrap($having['column']);
        $parameter = $this->parameter($having['value']);
        return $column . ' ' . $having['operator'] . ' ' . $parameter;
    }
    protected function compileHavingBetween($having)
    {
        $between = $having['not'] ? 'not between' : 'between';
        $column = $this->wrap($having['column']);
        $min = $this->parameter(head($having['values']));
        $max = $this->parameter(last($having['values']));
        return $column . ' ' . $between . ' ' . $min . ' and ' . $max;
    }
    protected function compileHavingNull($having)
    {
        $column = $this->wrap($having['column']);
        return $column . ' is null';
    }
    protected function compileHavingNotNull($having)
    {
        $column = $this->wrap($having['column']);
        return $column . ' is not null';
    }
    protected function compileHavingBit($having)
    {
        $column = $this->wrap($having['column']);
        $parameter = $this->parameter($having['value']);
        return '(' . $column . ' ' . $having['operator'] . ' ' . $parameter . ') != 0';
    }
    protected function compileHavingExpression($having)
    {
        return $having['column']->getValue($this);
    }
    protected function compileNestedHavings($having)
    {
        return '(' . substr($this->compileHavings($having['query']), 7) . ')';
    }
    protected function compileOrders(Builder $query, $orders)
    {
        if (!empty($orders)) {
            return 'order by ' . implode(', ', $this->compileOrdersToArray($query, $orders));
        }
        return '';
    }
    protected function compileOrdersToArray(Builder $query, $orders)
    {
        return array_map(function ($order) {
            return $order['sql'] ?? $this->wrap($order['column']) . ' ' . $order['direction'];
        }, $orders);
    }
    public function compileRandom($seed)
    {
        return 'RANDOM()';
    }
    protected function compileLimit(Builder $query, $limit)
    {
        return 'limit ' . (int) $limit;
    }
    protected function compileOffset(Builder $query, $offset)
    {
        return 'offset ' . (int) $offset;
    }
    protected function compileUnions(Builder $query)
    {
        $sql = '';
        foreach ($query->unions as $union) {
            $sql .= $this->compileUnion($union);
        }
        if (!empty($query->unionOrders)) {
            $sql .= ' ' . $this->compileOrders($query, $query->unionOrders);
        }
        if (isset($query->unionLimit)) {
            $sql .= ' ' . $this->compileLimit($query, $query->unionLimit);
        }
        if (isset($query->unionOffset)) {
            $sql .= ' ' . $this->compileOffset($query, $query->unionOffset);
        }
        return ltrim($sql);
    }
    protected function compileUnion(array $union)
    {
        $conjunction = $union['all'] ? ' union all ' : ' union ';
        return $conjunction . $this->wrapUnion($union['query']->toSql());
    }
    protected function wrapUnion($sql)
    {
        return '(' . $sql . ')';
    }
    protected function compileUnionAggregate(Builder $query)
    {
        $sql = $this->compileAggregate($query, $query->aggregate);
        $query->aggregate = null;
        return $sql . ' from (' . $this->compileSelect($query) . ') as ' . $this->wrapTable('temp_table');
    }
    public function compileExists(Builder $query)
    {
        $select = $this->compileSelect($query);
        return "select exists({$select}) as {$this->wrap('exists')}";
    }
    public function compileInsert(Builder $query, array $values)
    {
        $table = $this->wrapTable($query->from);
        if (empty($values)) {
            return "insert into {$table} default values";
        }
        if (!is_array(reset($values))) {
            $values = [$values];
        }
        $columns = $this->columnize(array_keys(reset($values)));
        $parameters = collect($values)->map(function ($record) {
            return '(' . $this->parameterize($record) . ')';
        })->implode(', ');
        return "insert into {$table} ({$columns}) values {$parameters}";
    }
    public function compileInsertOrIgnore(Builder $query, array $values)
    {
        throw new RuntimeException('This database engine does not support inserting while ignoring errors.');
    }
    public function compileInsertGetId(Builder $query, $values, $sequence)
    {
        return $this->compileInsert($query, $values);
    }
    public function compileInsertUsing(Builder $query, array $columns, string $sql)
    {
        $table = $this->wrapTable($query->from);
        if (empty($columns) || $columns === ['*']) {
            return "insert into {$table} {$sql}";
        }
        return "insert into {$table} ({$this->columnize($columns)}) {$sql}";
    }
    public function compileInsertOrIgnoreUsing(Builder $query, array $columns, string $sql)
    {
        throw new RuntimeException('This database engine does not support inserting while ignoring errors.');
    }
    public function compileUpdate(Builder $query, array $values)
    {
        $table = $this->wrapTable($query->from);
        $columns = $this->compileUpdateColumns($query, $values);
        $where = $this->compileWheres($query);
        return trim(isset($query->joins) ? $this->compileUpdateWithJoins($query, $table, $columns, $where) : $this->compileUpdateWithoutJoins($query, $table, $columns, $where));
    }
    protected function compileUpdateColumns(Builder $query, array $values)
    {
        return collect($values)->map(function ($value, $key) {
            return $this->wrap($key) . ' = ' . $this->parameter($value);
        })->implode(', ');
    }
    protected function compileUpdateWithoutJoins(Builder $query, $table, $columns, $where)
    {
        return "update {$table} set {$columns} {$where}";
    }
    protected function compileUpdateWithJoins(Builder $query, $table, $columns, $where)
    {
        $joins = $this->compileJoins($query, $query->joins);
        return "update {$table} {$joins} set {$columns} {$where}";
    }
    public function compileUpsert(Builder $query, array $values, array $uniqueBy, array $update)
    {
        throw new RuntimeException('This database engine does not support upserts.');
    }
    public function prepareBindingsForUpdate(array $bindings, array $values)
    {
        $cleanBindings = Arr::except($bindings, ['select', 'join']);
        return array_values(array_merge($bindings['join'], $values, Arr::flatten($cleanBindings)));
    }
    public function compileDelete(Builder $query)
    {
        $table = $this->wrapTable($query->from);
        $where = $this->compileWheres($query);
        return trim(isset($query->joins) ? $this->compileDeleteWithJoins($query, $table, $where) : $this->compileDeleteWithoutJoins($query, $table, $where));
    }
    protected function compileDeleteWithoutJoins(Builder $query, $table, $where)
    {
        return "delete from {$table} {$where}";
    }
    protected function compileDeleteWithJoins(Builder $query, $table, $where)
    {
        $alias = last(explode(' as ', $table));
        $joins = $this->compileJoins($query, $query->joins);
        return "delete {$alias} from {$table} {$joins} {$where}";
    }
    public function prepareBindingsForDelete(array $bindings)
    {
        return Arr::flatten(Arr::except($bindings, 'select'));
    }
    public function compileTruncate(Builder $query)
    {
        return ['truncate table ' . $this->wrapTable($query->from) => []];
    }
    protected function compileLock(Builder $query, $value)
    {
        return is_string($value) ? $value : '';
    }
    public function supportsSavepoints()
    {
        return true;
    }
    public function compileSavepoint($name)
    {
        return 'SAVEPOINT ' . $name;
    }
    public function compileSavepointRollBack($name)
    {
        return 'ROLLBACK TO SAVEPOINT ' . $name;
    }
    protected function wrapJsonBooleanSelector($value)
    {
        return $this->wrapJsonSelector($value);
    }
    protected function wrapJsonBooleanValue($value)
    {
        return $value;
    }
    protected function concatenate($segments)
    {
        return implode(' ', array_filter($segments, function ($value) {
            return (string) $value !== '';
        }));
    }
    protected function removeLeadingBoolean($value)
    {
        return preg_replace('/and |or /i', '', $value, 1);
    }
    public function substituteBindingsIntoRawSql($sql, $bindings)
    {
        $bindings = array_map(fn($value) => $this->escape($value), $bindings);
        $query = '';
        $isStringLiteral = false;
        for ($i = 0; $i < strlen($sql); $i++) {
            $char = $sql[$i];
            $nextChar = $sql[$i + 1] ?? null;
            if (in_array($char . $nextChar, ["\\'", "''", '??'])) {
                $query .= $char . $nextChar;
                $i += 1;
            } elseif ($char === "'") {
                $query .= $char;
                $isStringLiteral = !$isStringLiteral;
            } elseif ($char === '?' && !$isStringLiteral) {
                $query .= array_shift($bindings) ?? '?';
            } else {
                $query .= $char;
            }
        }
        return $query;
    }
    public function getOperators()
    {
        return $this->operators;
    }
    public function getBitwiseOperators()
    {
        return $this->bitwiseOperators;
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\JoinLateralClause;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
class SqlServerGrammar extends Grammar
{
    protected $operators = ['=', '<', '>', '<=', '>=', '!<', '!>', '<>', '!=', 'like', 'not like', 'ilike', '&', '&=', '|', '|=', '^', '^='];
    protected $selectComponents = ['aggregate', 'columns', 'from', 'indexHint', 'joins', 'wheres', 'groups', 'havings', 'orders', 'offset', 'limit', 'lock'];
    public function compileSelect(Builder $query)
    {
        if ($query->offset && empty($query->orders)) {
            $query->orders[] = ['sql' => '(SELECT 0)'];
        }
        return parent::compileSelect($query);
    }
    protected function compileColumns(Builder $query, $columns)
    {
        if (!is_null($query->aggregate)) {
            return;
        }
        $select = $query->distinct ? 'select distinct ' : 'select ';
        if (is_numeric($query->limit) && $query->limit > 0 && $query->offset <= 0) {
            $select .= 'top ' . (int) $query->limit . ' ';
        }
        return $select . $this->columnize($columns);
    }
    protected function compileFrom(Builder $query, $table)
    {
        $from = parent::compileFrom($query, $table);
        if (is_string($query->lock)) {
            return $from . ' ' . $query->lock;
        }
        if (!is_null($query->lock)) {
            return $from . ' with(rowlock,' . ($query->lock ? 'updlock,' : '') . 'holdlock)';
        }
        return $from;
    }
    protected function compileIndexHint(Builder $query, $indexHint)
    {
        return $indexHint->type === 'force' ? "with (index({$indexHint->index}))" : '';
    }
    protected function whereBitwise(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        $operator = str_replace('?', '??', $where['operator']);
        return '(' . $this->wrap($where['column']) . ' ' . $operator . ' ' . $value . ') != 0';
    }
    protected function whereDate(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return 'cast(' . $this->wrap($where['column']) . ' as date) ' . $where['operator'] . ' ' . $value;
    }
    protected function whereTime(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return 'cast(' . $this->wrap($where['column']) . ' as time) ' . $where['operator'] . ' ' . $value;
    }
    protected function compileJsonContains($column, $value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($column);
        return $value . ' in (select [value] from openjson(' . $field . $path . '))';
    }
    public function prepareBindingForJsonContains($binding)
    {
        return is_bool($binding) ? json_encode($binding) : $binding;
    }
    protected function compileJsonContainsKey($column)
    {
        $segments = explode('->', $column);
        $lastSegment = array_pop($segments);
        if (preg_match('/\[([0-9]+)\]$/', $lastSegment, $matches)) {
            $segments[] = Str::beforeLast($lastSegment, $matches[0]);
            $key = $matches[1];
        } else {
            $key = "'" . str_replace("'", "''", $lastSegment) . "'";
        }
        [$field, $path] = $this->wrapJsonFieldAndPath(implode('->', $segments));
        return $key . ' in (select [key] from openjson(' . $field . $path . '))';
    }
    protected function compileJsonLength($column, $operator, $value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($column);
        return '(select count(*) from openjson(' . $field . $path . ')) ' . $operator . ' ' . $value;
    }
    public function compileJsonValueCast($value)
    {
        return 'json_query(' . $value . ')';
    }
    protected function compileHaving(array $having)
    {
        if ($having['type'] === 'Bitwise') {
            return $this->compileHavingBitwise($having);
        }
        return parent::compileHaving($having);
    }
    protected function compileHavingBitwise($having)
    {
        $column = $this->wrap($having['column']);
        $parameter = $this->parameter($having['value']);
        return '(' . $column . ' ' . $having['operator'] . ' ' . $parameter . ') != 0';
    }
    protected function compileDeleteWithoutJoins(Builder $query, $table, $where)
    {
        $sql = parent::compileDeleteWithoutJoins($query, $table, $where);
        return !is_null($query->limit) && $query->limit > 0 && $query->offset <= 0 ? Str::replaceFirst('delete', 'delete top (' . $query->limit . ')', $sql) : $sql;
    }
    public function compileRandom($seed)
    {
        return 'NEWID()';
    }
    protected function compileLimit(Builder $query, $limit)
    {
        $limit = (int) $limit;
        if ($limit && $query->offset > 0) {
            return "fetch next {$limit} rows only";
        }
        return '';
    }
    protected function compileOffset(Builder $query, $offset)
    {
        $offset = (int) $offset;
        if ($offset) {
            return "offset {$offset} rows";
        }
        return '';
    }
    protected function compileLock(Builder $query, $value)
    {
        return '';
    }
    protected function wrapUnion($sql)
    {
        return 'select * from (' . $sql . ') as ' . $this->wrapTable('temp_table');
    }
    public function compileExists(Builder $query)
    {
        $existsQuery = clone $query;
        $existsQuery->columns = [];
        return $this->compileSelect($existsQuery->selectRaw('1 [exists]')->limit(1));
    }
    protected function compileUpdateWithJoins(Builder $query, $table, $columns, $where)
    {
        $alias = last(explode(' as ', $table));
        $joins = $this->compileJoins($query, $query->joins);
        return "update {$alias} set {$columns} from {$table} {$joins} {$where}";
    }
    public function compileUpsert(Builder $query, array $values, array $uniqueBy, array $update)
    {
        $columns = $this->columnize(array_keys(reset($values)));
        $sql = 'merge ' . $this->wrapTable($query->from) . ' ';
        $parameters = collect($values)->map(function ($record) {
            return '(' . $this->parameterize($record) . ')';
        })->implode(', ');
        $sql .= 'using (values ' . $parameters . ') ' . $this->wrapTable('laravel_source') . ' (' . $columns . ') ';
        $on = collect($uniqueBy)->map(function ($column) use ($query) {
            return $this->wrap('laravel_source.' . $column) . ' = ' . $this->wrap($query->from . '.' . $column);
        })->implode(' and ');
        $sql .= 'on ' . $on . ' ';
        if ($update) {
            $update = collect($update)->map(function ($value, $key) {
                return is_numeric($key) ? $this->wrap($value) . ' = ' . $this->wrap('laravel_source.' . $value) : $this->wrap($key) . ' = ' . $this->parameter($value);
            })->implode(', ');
            $sql .= 'when matched then update set ' . $update . ' ';
        }
        $sql .= 'when not matched then insert (' . $columns . ') values (' . $columns . ');';
        return $sql;
    }
    public function prepareBindingsForUpdate(array $bindings, array $values)
    {
        $cleanBindings = Arr::except($bindings, 'select');
        return array_values(array_merge($values, Arr::flatten($cleanBindings)));
    }
    public function compileJoinLateral(JoinLateralClause $join, string $expression): string
    {
        $type = $join->type == 'left' ? 'outer' : 'cross';
        return trim("{$type} apply {$expression}");
    }
    public function compileSavepoint($name)
    {
        return 'SAVE TRANSACTION ' . $name;
    }
    public function compileSavepointRollBack($name)
    {
        return 'ROLLBACK TRANSACTION ' . $name;
    }
    public function getDateFormat()
    {
        return 'Y-m-d H:i:s.v';
    }
    protected function wrapValue($value)
    {
        return $value === '*' ? $value : '[' . str_replace(']', ']]', $value) . ']';
    }
    protected function wrapJsonSelector($value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($value);
        return 'json_value(' . $field . $path . ')';
    }
    protected function wrapJsonBooleanValue($value)
    {
        return "'" . $value . "'";
    }
    public function wrapTable($table)
    {
        if (!$this->isExpression($table)) {
            return $this->wrapTableValuedFunction(parent::wrapTable($table));
        }
        return $this->getValue($table);
    }
    protected function wrapTableValuedFunction($table)
    {
        if (preg_match('/^(.+?)(\(.*?\))]$/', $table, $matches) === 1) {
            $table = $matches[1] . ']' . $matches[2];
        }
        return $table;
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\JoinLateralClause;
use Illuminate\Support\Str;
class MySqlGrammar extends Grammar
{
    protected $operators = ['sounds like'];
    protected function whereNull(Builder $query, $where)
    {
        $columnValue = (string) $this->getValue($where['column']);
        if ($this->isJsonSelector($columnValue)) {
            [$field, $path] = $this->wrapJsonFieldAndPath($columnValue);
            return '(json_extract(' . $field . $path . ') is null OR json_type(json_extract(' . $field . $path . ')) = \'NULL\')';
        }
        return parent::whereNull($query, $where);
    }
    protected function whereNotNull(Builder $query, $where)
    {
        $columnValue = (string) $this->getValue($where['column']);
        if ($this->isJsonSelector($columnValue)) {
            [$field, $path] = $this->wrapJsonFieldAndPath($columnValue);
            return '(json_extract(' . $field . $path . ') is not null AND json_type(json_extract(' . $field . $path . ')) != \'NULL\')';
        }
        return parent::whereNotNull($query, $where);
    }
    public function whereFullText(Builder $query, $where)
    {
        $columns = $this->columnize($where['columns']);
        $value = $this->parameter($where['value']);
        $mode = ($where['options']['mode'] ?? []) === 'boolean' ? ' in boolean mode' : ' in natural language mode';
        $expanded = ($where['options']['expanded'] ?? []) && ($where['options']['mode'] ?? []) !== 'boolean' ? ' with query expansion' : '';
        return "match ({$columns}) against (" . $value . "{$mode}{$expanded})";
    }
    protected function compileIndexHint(Builder $query, $indexHint)
    {
        return match ($indexHint->type) {
            'hint' => "use index ({$indexHint->index})",
            'force' => "force index ({$indexHint->index})",
            default => "ignore index ({$indexHint->index})",
        };
    }
    public function compileInsertOrIgnore(Builder $query, array $values)
    {
        return Str::replaceFirst('insert', 'insert ignore', $this->compileInsert($query, $values));
    }
    public function compileInsertOrIgnoreUsing(Builder $query, array $columns, string $sql)
    {
        return Str::replaceFirst('insert', 'insert ignore', $this->compileInsertUsing($query, $columns, $sql));
    }
    protected function compileJsonContains($column, $value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($column);
        return 'json_contains(' . $field . ', ' . $value . $path . ')';
    }
    protected function compileJsonContainsKey($column)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($column);
        return 'ifnull(json_contains_path(' . $field . ', \'one\'' . $path . '), 0)';
    }
    protected function compileJsonLength($column, $operator, $value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($column);
        return 'json_length(' . $field . $path . ') ' . $operator . ' ' . $value;
    }
    public function compileJsonValueCast($value)
    {
        return 'cast(' . $value . ' as json)';
    }
    public function compileRandom($seed)
    {
        return 'RAND(' . $seed . ')';
    }
    protected function compileLock(Builder $query, $value)
    {
        if (!is_string($value)) {
            return $value ? 'for update' : 'lock in share mode';
        }
        return $value;
    }
    public function compileInsert(Builder $query, array $values)
    {
        if (empty($values)) {
            $values = [[]];
        }
        return parent::compileInsert($query, $values);
    }
    protected function compileUpdateColumns(Builder $query, array $values)
    {
        return collect($values)->map(function ($value, $key) {
            if ($this->isJsonSelector($key)) {
                return $this->compileJsonUpdateColumn($key, $value);
            }
            return $this->wrap($key) . ' = ' . $this->parameter($value);
        })->implode(', ');
    }
    public function compileUpsert(Builder $query, array $values, array $uniqueBy, array $update)
    {
        $useUpsertAlias = $query->connection->getConfig('use_upsert_alias');
        $sql = $this->compileInsert($query, $values);
        if ($useUpsertAlias) {
            $sql .= ' as laravel_upsert_alias';
        }
        $sql .= ' on duplicate key update ';
        $columns = collect($update)->map(function ($value, $key) use ($useUpsertAlias) {
            if (!is_numeric($key)) {
                return $this->wrap($key) . ' = ' . $this->parameter($value);
            }
            return $useUpsertAlias ? $this->wrap($value) . ' = ' . $this->wrap('laravel_upsert_alias') . '.' . $this->wrap($value) : $this->wrap($value) . ' = values(' . $this->wrap($value) . ')';
        })->implode(', ');
        return $sql . $columns;
    }
    public function compileJoinLateral(JoinLateralClause $join, string $expression): string
    {
        return trim("{$join->type} join lateral {$expression} on true");
    }
    protected function compileJsonUpdateColumn($key, $value)
    {
        if (is_bool($value)) {
            $value = $value ? 'true' : 'false';
        } elseif (is_array($value)) {
            $value = 'cast(? as json)';
        } else {
            $value = $this->parameter($value);
        }
        [$field, $path] = $this->wrapJsonFieldAndPath($key);
        return "{$field} = json_set({$field}{$path}, {$value})";
    }
    protected function compileUpdateWithoutJoins(Builder $query, $table, $columns, $where)
    {
        $sql = parent::compileUpdateWithoutJoins($query, $table, $columns, $where);
        if (!empty($query->orders)) {
            $sql .= ' ' . $this->compileOrders($query, $query->orders);
        }
        if (isset($query->limit)) {
            $sql .= ' ' . $this->compileLimit($query, $query->limit);
        }
        return $sql;
    }
    public function prepareBindingsForUpdate(array $bindings, array $values)
    {
        $values = collect($values)->reject(function ($value, $column) {
            return $this->isJsonSelector($column) && is_bool($value);
        })->map(function ($value) {
            return is_array($value) ? json_encode($value) : $value;
        })->all();
        return parent::prepareBindingsForUpdate($bindings, $values);
    }
    protected function compileDeleteWithoutJoins(Builder $query, $table, $where)
    {
        $sql = parent::compileDeleteWithoutJoins($query, $table, $where);
        if (!empty($query->orders)) {
            $sql .= ' ' . $this->compileOrders($query, $query->orders);
        }
        if (isset($query->limit)) {
            $sql .= ' ' . $this->compileLimit($query, $query->limit);
        }
        return $sql;
    }
    protected function wrapValue($value)
    {
        return $value === '*' ? $value : '`' . str_replace('`', '``', $value) . '`';
    }
    protected function wrapJsonSelector($value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($value);
        return 'json_unquote(json_extract(' . $field . $path . '))';
    }
    protected function wrapJsonBooleanSelector($value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($value);
        return 'json_extract(' . $field . $path . ')';
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\JoinLateralClause;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
class PostgresGrammar extends Grammar
{
    protected $operators = ['=', '<', '>', '<=', '>=', '<>', '!=', 'like', 'not like', 'between', 'ilike', 'not ilike', '~', '&', '|', '#', '<<', '>>', '<<=', '>>=', '&&', '@>', '<@', '?', '?|', '?&', '||', '-', '@?', '@@', '#-', 'is distinct from', 'is not distinct from'];
    protected $bitwiseOperators = ['~', '&', '|', '#', '<<', '>>', '<<=', '>>='];
    protected function whereBasic(Builder $query, $where)
    {
        if (str_contains(strtolower($where['operator']), 'like')) {
            return sprintf('%s::text %s %s', $this->wrap($where['column']), $where['operator'], $this->parameter($where['value']));
        }
        return parent::whereBasic($query, $where);
    }
    protected function whereBitwise(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        $operator = str_replace('?', '??', $where['operator']);
        return '(' . $this->wrap($where['column']) . ' ' . $operator . ' ' . $value . ')::bool';
    }
    protected function whereDate(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return $this->wrap($where['column']) . '::date ' . $where['operator'] . ' ' . $value;
    }
    protected function whereTime(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return $this->wrap($where['column']) . '::time ' . $where['operator'] . ' ' . $value;
    }
    protected function dateBasedWhere($type, Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return 'extract(' . $type . ' from ' . $this->wrap($where['column']) . ') ' . $where['operator'] . ' ' . $value;
    }
    public function whereFullText(Builder $query, $where)
    {
        $language = $where['options']['language'] ?? 'english';
        if (!in_array($language, $this->validFullTextLanguages())) {
            $language = 'english';
        }
        $columns = collect($where['columns'])->map(function ($column) use ($language) {
            return "to_tsvector('{$language}', {$this->wrap($column)})";
        })->implode(' || ');
        $mode = 'plainto_tsquery';
        if (($where['options']['mode'] ?? []) === 'phrase') {
            $mode = 'phraseto_tsquery';
        }
        if (($where['options']['mode'] ?? []) === 'websearch') {
            $mode = 'websearch_to_tsquery';
        }
        return "({$columns}) @@ {$mode}('{$language}', {$this->parameter($where['value'])})";
    }
    protected function validFullTextLanguages()
    {
        return ['simple', 'arabic', 'danish', 'dutch', 'english', 'finnish', 'french', 'german', 'hungarian', 'indonesian', 'irish', 'italian', 'lithuanian', 'nepali', 'norwegian', 'portuguese', 'romanian', 'russian', 'spanish', 'swedish', 'tamil', 'turkish'];
    }
    protected function compileColumns(Builder $query, $columns)
    {
        if (!is_null($query->aggregate)) {
            return;
        }
        if (is_array($query->distinct)) {
            $select = 'select distinct on (' . $this->columnize($query->distinct) . ') ';
        } elseif ($query->distinct) {
            $select = 'select distinct ';
        } else {
            $select = 'select ';
        }
        return $select . $this->columnize($columns);
    }
    protected function compileJsonContains($column, $value)
    {
        $column = str_replace('->>', '->', $this->wrap($column));
        return '(' . $column . ')::jsonb @> ' . $value;
    }
    protected function compileJsonContainsKey($column)
    {
        $segments = explode('->', $column);
        $lastSegment = array_pop($segments);
        if (filter_var($lastSegment, FILTER_VALIDATE_INT) !== false) {
            $i = $lastSegment;
        } elseif (preg_match('/\[(-?[0-9]+)\]$/', $lastSegment, $matches)) {
            $segments[] = Str::beforeLast($lastSegment, $matches[0]);
            $i = $matches[1];
        }
        $column = str_replace('->>', '->', $this->wrap(implode('->', $segments)));
        if (isset($i)) {
            return vsprintf('case when %s then %s else false end', ['jsonb_typeof((' . $column . ")::jsonb) = 'array'", 'jsonb_array_length((' . $column . ')::jsonb) >= ' . ($i < 0 ? abs($i) : $i + 1)]);
        }
        $key = "'" . str_replace("'", "''", $lastSegment) . "'";
        return 'coalesce((' . $column . ')::jsonb ?? ' . $key . ', false)';
    }
    protected function compileJsonLength($column, $operator, $value)
    {
        $column = str_replace('->>', '->', $this->wrap($column));
        return 'jsonb_array_length((' . $column . ')::jsonb) ' . $operator . ' ' . $value;
    }
    protected function compileHaving(array $having)
    {
        if ($having['type'] === 'Bitwise') {
            return $this->compileHavingBitwise($having);
        }
        return parent::compileHaving($having);
    }
    protected function compileHavingBitwise($having)
    {
        $column = $this->wrap($having['column']);
        $parameter = $this->parameter($having['value']);
        return '(' . $column . ' ' . $having['operator'] . ' ' . $parameter . ')::bool';
    }
    protected function compileLock(Builder $query, $value)
    {
        if (!is_string($value)) {
            return $value ? 'for update' : 'for share';
        }
        return $value;
    }
    public function compileInsertOrIgnore(Builder $query, array $values)
    {
        return $this->compileInsert($query, $values) . ' on conflict do nothing';
    }
    public function compileInsertOrIgnoreUsing(Builder $query, array $columns, string $sql)
    {
        return $this->compileInsertUsing($query, $columns, $sql) . ' on conflict do nothing';
    }
    public function compileInsertGetId(Builder $query, $values, $sequence)
    {
        return $this->compileInsert($query, $values) . ' returning ' . $this->wrap($sequence ?: 'id');
    }
    public function compileUpdate(Builder $query, array $values)
    {
        if (isset($query->joins) || isset($query->limit)) {
            return $this->compileUpdateWithJoinsOrLimit($query, $values);
        }
        return parent::compileUpdate($query, $values);
    }
    protected function compileUpdateColumns(Builder $query, array $values)
    {
        return collect($values)->map(function ($value, $key) {
            $column = last(explode('.', $key));
            if ($this->isJsonSelector($key)) {
                return $this->compileJsonUpdateColumn($column, $value);
            }
            return $this->wrap($column) . ' = ' . $this->parameter($value);
        })->implode(', ');
    }
    public function compileUpsert(Builder $query, array $values, array $uniqueBy, array $update)
    {
        $sql = $this->compileInsert($query, $values);
        $sql .= ' on conflict (' . $this->columnize($uniqueBy) . ') do update set ';
        $columns = collect($update)->map(function ($value, $key) {
            return is_numeric($key) ? $this->wrap($value) . ' = ' . $this->wrapValue('excluded') . '.' . $this->wrap($value) : $this->wrap($key) . ' = ' . $this->parameter($value);
        })->implode(', ');
        return $sql . $columns;
    }
    public function compileJoinLateral(JoinLateralClause $join, string $expression): string
    {
        return trim("{$join->type} join lateral {$expression} on true");
    }
    protected function compileJsonUpdateColumn($key, $value)
    {
        $segments = explode('->', $key);
        $field = $this->wrap(array_shift($segments));
        $path = "'{" . implode(',', $this->wrapJsonPathAttributes($segments, '"')) . "}'";
        return "{$field} = jsonb_set({$field}::jsonb, {$path}, {$this->parameter($value)})";
    }
    public function compileUpdateFrom(Builder $query, $values)
    {
        $table = $this->wrapTable($query->from);
        $columns = $this->compileUpdateColumns($query, $values);
        $from = '';
        if (isset($query->joins)) {
            $froms = collect($query->joins)->map(function ($join) {
                return $this->wrapTable($join->table);
            })->all();
            if (count($froms) > 0) {
                $from = ' from ' . implode(', ', $froms);
            }
        }
        $where = $this->compileUpdateWheres($query);
        return trim("update {$table} set {$columns}{$from} {$where}");
    }
    protected function compileUpdateWheres(Builder $query)
    {
        $baseWheres = $this->compileWheres($query);
        if (!isset($query->joins)) {
            return $baseWheres;
        }
        $joinWheres = $this->compileUpdateJoinWheres($query);
        if (trim($baseWheres) == '') {
            return 'where ' . $this->removeLeadingBoolean($joinWheres);
        }
        return $baseWheres . ' ' . $joinWheres;
    }
    protected function compileUpdateJoinWheres(Builder $query)
    {
        $joinWheres = [];
        foreach ($query->joins as $join) {
            foreach ($join->wheres as $where) {
                $method = "where{$where['type']}";
                $joinWheres[] = $where['boolean'] . ' ' . $this->{$method}($query, $where);
            }
        }
        return implode(' ', $joinWheres);
    }
    public function prepareBindingsForUpdateFrom(array $bindings, array $values)
    {
        $values = collect($values)->map(function ($value, $column) {
            return is_array($value) || $this->isJsonSelector($column) && !$this->isExpression($value) ? json_encode($value) : $value;
        })->all();
        $bindingsWithoutWhere = Arr::except($bindings, ['select', 'where']);
        return array_values(array_merge($values, $bindings['where'], Arr::flatten($bindingsWithoutWhere)));
    }
    protected function compileUpdateWithJoinsOrLimit(Builder $query, array $values)
    {
        $table = $this->wrapTable($query->from);
        $columns = $this->compileUpdateColumns($query, $values);
        $alias = last(preg_split('/\s+as\s+/i', $query->from));
        $selectSql = $this->compileSelect($query->select($alias . '.ctid'));
        return "update {$table} set {$columns} where {$this->wrap('ctid')} in ({$selectSql})";
    }
    public function prepareBindingsForUpdate(array $bindings, array $values)
    {
        $values = collect($values)->map(function ($value, $column) {
            return is_array($value) || $this->isJsonSelector($column) && !$this->isExpression($value) ? json_encode($value) : $value;
        })->all();
        $cleanBindings = Arr::except($bindings, 'select');
        return array_values(array_merge($values, Arr::flatten($cleanBindings)));
    }
    public function compileDelete(Builder $query)
    {
        if (isset($query->joins) || isset($query->limit)) {
            return $this->compileDeleteWithJoinsOrLimit($query);
        }
        return parent::compileDelete($query);
    }
    protected function compileDeleteWithJoinsOrLimit(Builder $query)
    {
        $table = $this->wrapTable($query->from);
        $alias = last(preg_split('/\s+as\s+/i', $query->from));
        $selectSql = $this->compileSelect($query->select($alias . '.ctid'));
        return "delete from {$table} where {$this->wrap('ctid')} in ({$selectSql})";
    }
    public function compileTruncate(Builder $query)
    {
        return ['truncate ' . $this->wrapTable($query->from) . ' restart identity cascade' => []];
    }
    protected function wrapJsonSelector($value)
    {
        $path = explode('->', $value);
        $field = $this->wrapSegments(explode('.', array_shift($path)));
        $wrappedPath = $this->wrapJsonPathAttributes($path);
        $attribute = array_pop($wrappedPath);
        if (!empty($wrappedPath)) {
            return $field . '->' . implode('->', $wrappedPath) . '->>' . $attribute;
        }
        return $field . '->>' . $attribute;
    }
    protected function wrapJsonBooleanSelector($value)
    {
        $selector = str_replace('->>', '->', $this->wrapJsonSelector($value));
        return '(' . $selector . ')::jsonb';
    }
    protected function wrapJsonBooleanValue($value)
    {
        return "'" . $value . "'::jsonb";
    }
    protected function wrapJsonPathAttributes($path)
    {
        $quote = func_num_args() === 2 ? func_get_arg(1) : "'";
        return collect($path)->map(function ($attribute) {
            return $this->parseJsonPathArrayKeys($attribute);
        })->collapse()->map(function ($attribute) use ($quote) {
            return filter_var($attribute, FILTER_VALIDATE_INT) !== false ? $attribute : $quote . $attribute . $quote;
        })->all();
    }
    protected function parseJsonPathArrayKeys($attribute)
    {
        if (preg_match('/(\[[^\]]+\])+$/', $attribute, $parts)) {
            $key = Str::beforeLast($attribute, $parts[0]);
            preg_match_all('/\[([^\]]+)\]/', $parts[0], $keys);
            return collect([$key])->merge($keys[1])->diff('')->values()->all();
        }
        return [$attribute];
    }
    public function substituteBindingsIntoRawSql($sql, $bindings)
    {
        $query = parent::substituteBindingsIntoRawSql($sql, $bindings);
        foreach ($this->operators as $operator) {
            if (!str_contains($operator, '?')) {
                continue;
            }
            $query = str_replace(str_replace('?', '??', $operator), $operator, $query);
        }
        return $query;
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
class SQLiteGrammar extends Grammar
{
    protected $operators = ['=', '<', '>', '<=', '>=', '<>', '!=', 'like', 'not like', 'ilike', '&', '|', '<<', '>>'];
    protected function compileLock(Builder $query, $value)
    {
        return '';
    }
    protected function wrapUnion($sql)
    {
        return 'select * from (' . $sql . ')';
    }
    protected function whereDate(Builder $query, $where)
    {
        return $this->dateBasedWhere('%Y-%m-%d', $query, $where);
    }
    protected function whereDay(Builder $query, $where)
    {
        return $this->dateBasedWhere('%d', $query, $where);
    }
    protected function whereMonth(Builder $query, $where)
    {
        return $this->dateBasedWhere('%m', $query, $where);
    }
    protected function whereYear(Builder $query, $where)
    {
        return $this->dateBasedWhere('%Y', $query, $where);
    }
    protected function whereTime(Builder $query, $where)
    {
        return $this->dateBasedWhere('%H:%M:%S', $query, $where);
    }
    protected function dateBasedWhere($type, Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return "strftime('{$type}', {$this->wrap($where['column'])}) {$where['operator']} cast({$value} as text)";
    }
    protected function compileIndexHint(Builder $query, $indexHint)
    {
        return $indexHint->type === 'force' ? "indexed by {$indexHint->index}" : '';
    }
    protected function compileJsonLength($column, $operator, $value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($column);
        return 'json_array_length(' . $field . $path . ') ' . $operator . ' ' . $value;
    }
    protected function compileJsonContains($column, $value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($column);
        return 'exists (select 1 from json_each(' . $field . $path . ') where ' . $this->wrap('json_each.value') . ' is ' . $value . ')';
    }
    public function prepareBindingForJsonContains($binding)
    {
        return $binding;
    }
    protected function compileJsonContainsKey($column)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($column);
        return 'json_type(' . $field . $path . ') is not null';
    }
    public function compileUpdate(Builder $query, array $values)
    {
        if (isset($query->joins) || isset($query->limit)) {
            return $this->compileUpdateWithJoinsOrLimit($query, $values);
        }
        return parent::compileUpdate($query, $values);
    }
    public function compileInsertOrIgnore(Builder $query, array $values)
    {
        return Str::replaceFirst('insert', 'insert or ignore', $this->compileInsert($query, $values));
    }
    public function compileInsertOrIgnoreUsing(Builder $query, array $columns, string $sql)
    {
        return Str::replaceFirst('insert', 'insert or ignore', $this->compileInsertUsing($query, $columns, $sql));
    }
    protected function compileUpdateColumns(Builder $query, array $values)
    {
        $jsonGroups = $this->groupJsonColumnsForUpdate($values);
        return collect($values)->reject(function ($value, $key) {
            return $this->isJsonSelector($key);
        })->merge($jsonGroups)->map(function ($value, $key) use ($jsonGroups) {
            $column = last(explode('.', $key));
            $value = isset($jsonGroups[$key]) ? $this->compileJsonPatch($column, $value) : $this->parameter($value);
            return $this->wrap($column) . ' = ' . $value;
        })->implode(', ');
    }
    public function compileUpsert(Builder $query, array $values, array $uniqueBy, array $update)
    {
        $sql = $this->compileInsert($query, $values);
        $sql .= ' on conflict (' . $this->columnize($uniqueBy) . ') do update set ';
        $columns = collect($update)->map(function ($value, $key) {
            return is_numeric($key) ? $this->wrap($value) . ' = ' . $this->wrapValue('excluded') . '.' . $this->wrap($value) : $this->wrap($key) . ' = ' . $this->parameter($value);
        })->implode(', ');
        return $sql . $columns;
    }
    protected function groupJsonColumnsForUpdate(array $values)
    {
        $groups = [];
        foreach ($values as $key => $value) {
            if ($this->isJsonSelector($key)) {
                Arr::set($groups, str_replace('->', '.', Str::after($key, '.')), $value);
            }
        }
        return $groups;
    }
    protected function compileJsonPatch($column, $value)
    {
        return "json_patch(ifnull({$this->wrap($column)}, json('{}')), json({$this->parameter($value)}))";
    }
    protected function compileUpdateWithJoinsOrLimit(Builder $query, array $values)
    {
        $table = $this->wrapTable($query->from);
        $columns = $this->compileUpdateColumns($query, $values);
        $alias = last(preg_split('/\s+as\s+/i', $query->from));
        $selectSql = $this->compileSelect($query->select($alias . '.rowid'));
        return "update {$table} set {$columns} where {$this->wrap('rowid')} in ({$selectSql})";
    }
    public function prepareBindingsForUpdate(array $bindings, array $values)
    {
        $groups = $this->groupJsonColumnsForUpdate($values);
        $values = collect($values)->reject(function ($value, $key) {
            return $this->isJsonSelector($key);
        })->merge($groups)->map(function ($value) {
            return is_array($value) ? json_encode($value) : $value;
        })->all();
        $cleanBindings = Arr::except($bindings, 'select');
        return array_values(array_merge($values, Arr::flatten($cleanBindings)));
    }
    public function compileDelete(Builder $query)
    {
        if (isset($query->joins) || isset($query->limit)) {
            return $this->compileDeleteWithJoinsOrLimit($query);
        }
        return parent::compileDelete($query);
    }
    protected function compileDeleteWithJoinsOrLimit(Builder $query)
    {
        $table = $this->wrapTable($query->from);
        $alias = last(preg_split('/\s+as\s+/i', $query->from));
        $selectSql = $this->compileSelect($query->select($alias . '.rowid'));
        return "delete from {$table} where {$this->wrap('rowid')} in ({$selectSql})";
    }
    public function compileTruncate(Builder $query)
    {
        return ['delete from sqlite_sequence where name = ?' => [$this->getTablePrefix() . $query->from], 'delete from ' . $this->wrapTable($query->from) => []];
    }
    protected function wrapJsonSelector($value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($value);
        return 'json_extract(' . $field . $path . ')';
    }
}
}

namespace Illuminate\Database\Query {
use Illuminate\Contracts\Database\Query\Expression as ExpressionContract;
use Illuminate\Database\Grammar;
class Expression implements ExpressionContract
{
    protected $value;
    public function __construct($value)
    {
        $this->value = $value;
    }
    public function getValue(Grammar $grammar)
    {
        return $this->value;
    }
}
}

namespace Illuminate\Database\Query\Processors {
class SQLiteProcessor extends Processor
{
    public function processColumnListing($results)
    {
        return array_map(function ($result) {
            return ((object) $result)->name;
        }, $results);
    }
    public function processColumns($results)
    {
        $hasPrimaryKey = array_sum(array_column($results, 'primary')) === 1;
        return array_map(function ($result) use ($hasPrimaryKey) {
            $result = (object) $result;
            $type = strtolower($result->type);
            return ['name' => $result->name, 'type_name' => strtok($type, '(') ?: '', 'type' => $type, 'collation' => null, 'nullable' => (bool) $result->nullable, 'default' => $result->default, 'auto_increment' => $hasPrimaryKey && $result->primary && $type === 'integer', 'comment' => null];
        }, $results);
    }
    public function processIndexes($results)
    {
        $primaryCount = 0;
        $indexes = array_map(function ($result) use (&$primaryCount) {
            $result = (object) $result;
            if ($isPrimary = (bool) $result->primary) {
                $primaryCount += 1;
            }
            return ['name' => strtolower($result->name), 'columns' => explode(',', $result->columns), 'type' => null, 'unique' => (bool) $result->unique, 'primary' => $isPrimary];
        }, $results);
        if ($primaryCount > 1) {
            $indexes = array_filter($indexes, fn($index) => $index['name'] !== 'primary');
        }
        return $indexes;
    }
    public function processForeignKeys($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => null, 'columns' => explode(',', $result->columns), 'foreign_schema' => null, 'foreign_table' => $result->foreign_table, 'foreign_columns' => explode(',', $result->foreign_columns), 'on_update' => strtolower($result->on_update), 'on_delete' => strtolower($result->on_delete)];
        }, $results);
    }
}
}

namespace Illuminate\Database\Query\Processors {
use Illuminate\Database\Query\Builder;
class Processor
{
    public function processSelect(Builder $query, $results)
    {
        return $results;
    }
    public function processInsertGetId(Builder $query, $sql, $values, $sequence = null)
    {
        $query->getConnection()->insert($sql, $values);
        $id = $query->getConnection()->getPdo()->lastInsertId($sequence);
        return is_numeric($id) ? (int) $id : $id;
    }
    public function processTables($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => $result->name, 'schema' => $result->schema ?? null, 'size' => isset($result->size) ? (int) $result->size : null, 'comment' => $result->comment ?? null, 'collation' => $result->collation ?? null, 'engine' => $result->engine ?? null];
        }, $results);
    }
    public function processViews($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => $result->name, 'schema' => $result->schema ?? null, 'definition' => $result->definition];
        }, $results);
    }
    public function processTypes($results)
    {
        return $results;
    }
    public function processColumns($results)
    {
        return $results;
    }
    public function processIndexes($results)
    {
        return $results;
    }
    public function processForeignKeys($results)
    {
        return $results;
    }
    public function processColumnListing($results)
    {
        return $results;
    }
}
}

namespace Illuminate\Database\Query\Processors {
use Exception;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
class SqlServerProcessor extends Processor
{
    public function processInsertGetId(Builder $query, $sql, $values, $sequence = null)
    {
        $connection = $query->getConnection();
        $connection->insert($sql, $values);
        if ($connection->getConfig('odbc') === true) {
            $id = $this->processInsertGetIdForOdbc($connection);
        } else {
            $id = $connection->getPdo()->lastInsertId();
        }
        return is_numeric($id) ? (int) $id : $id;
    }
    protected function processInsertGetIdForOdbc(Connection $connection)
    {
        $result = $connection->selectFromWriteConnection('SELECT CAST(COALESCE(SCOPE_IDENTITY(), @@IDENTITY) AS int) AS insertid');
        if (!$result) {
            throw new Exception('Unable to retrieve lastInsertID for ODBC.');
        }
        $row = $result[0];
        return is_object($row) ? $row->insertid : $row['insertid'];
    }
    public function processColumnListing($results)
    {
        return array_map(function ($result) {
            return ((object) $result)->name;
        }, $results);
    }
    public function processColumns($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            $type = match ($typeName = $result->type_name) {
                'binary', 'varbinary', 'char', 'varchar', 'nchar', 'nvarchar' => $result->length == -1 ? $typeName . '(max)' : $typeName . "({$result->length})",
                'decimal', 'numeric' => $typeName . "({$result->precision},{$result->places})",
                'float', 'datetime2', 'datetimeoffset', 'time' => $typeName . "({$result->precision})",
                default => $typeName,
            };
            return ['name' => $result->name, 'type_name' => $result->type_name, 'type' => $type, 'collation' => $result->collation, 'nullable' => (bool) $result->nullable, 'default' => $result->default, 'auto_increment' => (bool) $result->autoincrement, 'comment' => $result->comment];
        }, $results);
    }
    public function processIndexes($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => strtolower($result->name), 'columns' => explode(',', $result->columns), 'type' => strtolower($result->type), 'unique' => (bool) $result->unique, 'primary' => (bool) $result->primary];
        }, $results);
    }
    public function processForeignKeys($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => $result->name, 'columns' => explode(',', $result->columns), 'foreign_schema' => $result->foreign_schema, 'foreign_table' => $result->foreign_table, 'foreign_columns' => explode(',', $result->foreign_columns), 'on_update' => strtolower(str_replace('_', ' ', $result->on_update)), 'on_delete' => strtolower(str_replace('_', ' ', $result->on_delete))];
        }, $results);
    }
}
}

namespace Illuminate\Database\Query\Processors {
use Illuminate\Database\Query\Builder;
class PostgresProcessor extends Processor
{
    public function processInsertGetId(Builder $query, $sql, $values, $sequence = null)
    {
        $connection = $query->getConnection();
        $connection->recordsHaveBeenModified();
        $result = $connection->selectFromWriteConnection($sql, $values)[0];
        $sequence = $sequence ?: 'id';
        $id = is_object($result) ? $result->{$sequence} : $result[$sequence];
        return is_numeric($id) ? (int) $id : $id;
    }
    public function processColumnListing($results)
    {
        return array_map(function ($result) {
            return ((object) $result)->column_name;
        }, $results);
    }
    public function processTypes($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => $result->name, 'schema' => $result->schema, 'implicit' => (bool) $result->implicit, 'type' => match (strtolower($result->type)) {
                'b' => 'base',
                'c' => 'composite',
                'd' => 'domain',
                'e' => 'enum',
                'p' => 'pseudo',
                'r' => 'range',
                'm' => 'multirange',
                default => null,
            }, 'category' => match (strtolower($result->category)) {
                'a' => 'array',
                'b' => 'boolean',
                'c' => 'composite',
                'd' => 'date_time',
                'e' => 'enum',
                'g' => 'geometric',
                'i' => 'network_address',
                'n' => 'numeric',
                'p' => 'pseudo',
                'r' => 'range',
                's' => 'string',
                't' => 'timespan',
                'u' => 'user_defined',
                'v' => 'bit_string',
                'x' => 'unknown',
                'z' => 'internal_use',
                default => null,
            }];
        }, $results);
    }
    public function processColumns($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            $autoincrement = $result->default !== null && str_starts_with($result->default, 'nextval(');
            return ['name' => $result->name, 'type_name' => $result->type_name, 'type' => $result->type, 'collation' => $result->collation, 'nullable' => (bool) $result->nullable, 'default' => $autoincrement ? null : $result->default, 'auto_increment' => $autoincrement, 'comment' => $result->comment];
        }, $results);
    }
    public function processIndexes($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => strtolower($result->name), 'columns' => explode(',', $result->columns), 'type' => strtolower($result->type), 'unique' => (bool) $result->unique, 'primary' => (bool) $result->primary];
        }, $results);
    }
    public function processForeignKeys($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => $result->name, 'columns' => explode(',', $result->columns), 'foreign_schema' => $result->foreign_schema, 'foreign_table' => $result->foreign_table, 'foreign_columns' => explode(',', $result->foreign_columns), 'on_update' => match (strtolower($result->on_update)) {
                'a' => 'no action',
                'r' => 'restrict',
                'c' => 'cascade',
                'n' => 'set null',
                'd' => 'set default',
                default => null,
            }, 'on_delete' => match (strtolower($result->on_delete)) {
                'a' => 'no action',
                'r' => 'restrict',
                'c' => 'cascade',
                'n' => 'set null',
                'd' => 'set default',
                default => null,
            }];
        }, $results);
    }
}
}

namespace Illuminate\Database\Query\Processors {
use Illuminate\Database\Query\Builder;
class MySqlProcessor extends Processor
{
    public function processColumnListing($results)
    {
        return array_map(function ($result) {
            return ((object) $result)->column_name;
        }, $results);
    }
    public function processInsertGetId(Builder $query, $sql, $values, $sequence = null)
    {
        $query->getConnection()->insert($sql, $values, $sequence);
        $id = $query->getConnection()->getLastInsertId();
        return is_numeric($id) ? (int) $id : $id;
    }
    public function processColumns($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => $result->name, 'type_name' => $result->type_name, 'type' => $result->type, 'collation' => $result->collation, 'nullable' => $result->nullable === 'YES', 'default' => $result->default, 'auto_increment' => $result->extra === 'auto_increment', 'comment' => $result->comment ?: null];
        }, $results);
    }
    public function processIndexes($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => $name = strtolower($result->name), 'columns' => explode(',', $result->columns), 'type' => strtolower($result->type), 'unique' => (bool) $result->unique, 'primary' => $name === 'primary'];
        }, $results);
    }
    public function processForeignKeys($results)
    {
        return array_map(function ($result) {
            $result = (object) $result;
            return ['name' => $result->name, 'columns' => explode(',', $result->columns), 'foreign_schema' => $result->foreign_schema, 'foreign_table' => $result->foreign_table, 'foreign_columns' => explode(',', $result->foreign_columns), 'on_update' => strtolower($result->on_update), 'on_delete' => strtolower($result->on_delete)];
        }, $results);
    }
}
}

namespace Illuminate\Database\Query {
use Closure;
class JoinClause extends Builder
{
    public $type;
    public $table;
    protected $parentConnection;
    protected $parentGrammar;
    protected $parentProcessor;
    protected $parentClass;
    public function __construct(Builder $parentQuery, $type, $table)
    {
        $this->type = $type;
        $this->table = $table;
        $this->parentClass = get_class($parentQuery);
        $this->parentGrammar = $parentQuery->getGrammar();
        $this->parentProcessor = $parentQuery->getProcessor();
        $this->parentConnection = $parentQuery->getConnection();
        parent::__construct($this->parentConnection, $this->parentGrammar, $this->parentProcessor);
    }
    public function on($first, $operator = null, $second = null, $boolean = 'and')
    {
        if ($first instanceof Closure) {
            return $this->whereNested($first, $boolean);
        }
        return $this->whereColumn($first, $operator, $second, $boolean);
    }
    public function orOn($first, $operator = null, $second = null)
    {
        return $this->on($first, $operator, $second, 'or');
    }
    public function newQuery()
    {
        return new static($this->newParentQuery(), $this->type, $this->table);
    }
    protected function forSubQuery()
    {
        return $this->newParentQuery()->newQuery();
    }
    protected function newParentQuery()
    {
        $class = $this->parentClass;
        return new $class($this->parentConnection, $this->parentGrammar, $this->parentProcessor);
    }
}
}

namespace Illuminate\Database {
use Closure;
interface ConnectionInterface
{
    public function table($table, $as = null);
    public function raw($value);
    public function selectOne($query, $bindings = [], $useReadPdo = true);
    public function select($query, $bindings = [], $useReadPdo = true);
    public function cursor($query, $bindings = [], $useReadPdo = true);
    public function insert($query, $bindings = []);
    public function update($query, $bindings = []);
    public function delete($query, $bindings = []);
    public function statement($query, $bindings = []);
    public function affectingStatement($query, $bindings = []);
    public function unprepared($query);
    public function prepareBindings(array $bindings);
    public function transaction(Closure $callback, $attempts = 1);
    public function beginTransaction();
    public function commit();
    public function rollBack();
    public function transactionLevel();
    public function pretend(Closure $callback);
    public function getDatabaseName();
}
}

namespace Illuminate\Database {
use Exception;
use Illuminate\Database\PDO\SQLiteDriver;
use Illuminate\Database\Query\Grammars\SQLiteGrammar as QueryGrammar;
use Illuminate\Database\Query\Processors\SQLiteProcessor;
use Illuminate\Database\Schema\Grammars\SQLiteGrammar as SchemaGrammar;
use Illuminate\Database\Schema\SQLiteBuilder;
use Illuminate\Database\Schema\SqliteSchemaState;
use Illuminate\Filesystem\Filesystem;
class SQLiteConnection extends Connection
{
    public function __construct($pdo, $database = '', $tablePrefix = '', array $config = [])
    {
        parent::__construct($pdo, $database, $tablePrefix, $config);
        $enableForeignKeyConstraints = $this->getForeignKeyConstraintsConfigurationValue();
        if ($enableForeignKeyConstraints === null) {
            return;
        }
        $enableForeignKeyConstraints ? $this->getSchemaBuilder()->enableForeignKeyConstraints() : $this->getSchemaBuilder()->disableForeignKeyConstraints();
    }
    protected function escapeBinary($value)
    {
        $hex = bin2hex($value);
        return "x'{$hex}'";
    }
    protected function isUniqueConstraintError(Exception $exception)
    {
        return boolval(preg_match('#(column(s)? .* (is|are) not unique|UNIQUE constraint failed: .*)#i', $exception->getMessage()));
    }
    protected function getDefaultQueryGrammar()
    {
        ($grammar = new QueryGrammar())->setConnection($this);
        return $this->withTablePrefix($grammar);
    }
    public function getSchemaBuilder()
    {
        if (is_null($this->schemaGrammar)) {
            $this->useDefaultSchemaGrammar();
        }
        return new SQLiteBuilder($this);
    }
    protected function getDefaultSchemaGrammar()
    {
        ($grammar = new SchemaGrammar())->setConnection($this);
        return $this->withTablePrefix($grammar);
    }
    public function getSchemaState(?Filesystem $files = null, ?callable $processFactory = null)
    {
        return new SqliteSchemaState($this, $files, $processFactory);
    }
    protected function getDefaultPostProcessor()
    {
        return new SQLiteProcessor();
    }
    protected function getDoctrineDriver()
    {
        return new SQLiteDriver();
    }
    protected function getForeignKeyConstraintsConfigurationValue()
    {
        return $this->getConfig('foreign_key_constraints');
    }
}
}

namespace Illuminate\Database\Connectors {
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Connection;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\PostgresConnection;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Database\SqlServerConnection;
use Illuminate\Support\Arr;
use InvalidArgumentException;
use PDOException;
class ConnectionFactory
{
    protected $container;
    public function __construct(Container $container)
    {
        $this->container = $container;
    }
    public function make(array $config, $name = null)
    {
        $config = $this->parseConfig($config, $name);
        if (isset($config['read'])) {
            return $this->createReadWriteConnection($config);
        }
        return $this->createSingleConnection($config);
    }
    protected function parseConfig(array $config, $name)
    {
        return Arr::add(Arr::add($config, 'prefix', ''), 'name', $name);
    }
    protected function createSingleConnection(array $config)
    {
        $pdo = $this->createPdoResolver($config);
        return $this->createConnection($config['driver'], $pdo, $config['database'], $config['prefix'], $config);
    }
    protected function createReadWriteConnection(array $config)
    {
        $connection = $this->createSingleConnection($this->getWriteConfig($config));
        return $connection->setReadPdo($this->createReadPdo($config));
    }
    protected function createReadPdo(array $config)
    {
        return $this->createPdoResolver($this->getReadConfig($config));
    }
    protected function getReadConfig(array $config)
    {
        return $this->mergeReadWriteConfig($config, $this->getReadWriteConfig($config, 'read'));
    }
    protected function getWriteConfig(array $config)
    {
        return $this->mergeReadWriteConfig($config, $this->getReadWriteConfig($config, 'write'));
    }
    protected function getReadWriteConfig(array $config, $type)
    {
        return isset($config[$type][0]) ? Arr::random($config[$type]) : $config[$type];
    }
    protected function mergeReadWriteConfig(array $config, array $merge)
    {
        return Arr::except(array_merge($config, $merge), ['read', 'write']);
    }
    protected function createPdoResolver(array $config)
    {
        return array_key_exists('host', $config) ? $this->createPdoResolverWithHosts($config) : $this->createPdoResolverWithoutHosts($config);
    }
    protected function createPdoResolverWithHosts(array $config)
    {
        return function () use ($config) {
            foreach (Arr::shuffle($this->parseHosts($config)) as $host) {
                $config['host'] = $host;
                try {
                    return $this->createConnector($config)->connect($config);
                } catch (PDOException $e) {
                    continue;
                }
            }
            throw $e;
        };
    }
    protected function parseHosts(array $config)
    {
        $hosts = Arr::wrap($config['host']);
        if (empty($hosts)) {
            throw new InvalidArgumentException('Database hosts array is empty.');
        }
        return $hosts;
    }
    protected function createPdoResolverWithoutHosts(array $config)
    {
        return fn() => $this->createConnector($config)->connect($config);
    }
    public function createConnector(array $config)
    {
        if (!isset($config['driver'])) {
            throw new InvalidArgumentException('A driver must be specified.');
        }
        if ($this->container->bound($key = "db.connector.{$config['driver']}")) {
            return $this->container->make($key);
        }
        return match ($config['driver']) {
            'mysql' => new MySqlConnector(),
            'pgsql' => new PostgresConnector(),
            'sqlite' => new SQLiteConnector(),
            'sqlsrv' => new SqlServerConnector(),
            default => throw new InvalidArgumentException("Unsupported driver [{$config['driver']}]."),
        };
    }
    protected function createConnection($driver, $connection, $database, $prefix = '', array $config = [])
    {
        if ($resolver = Connection::getResolver($driver)) {
            return $resolver($connection, $database, $prefix, $config);
        }
        return match ($driver) {
            'mysql' => new MySqlConnection($connection, $database, $prefix, $config),
            'pgsql' => new PostgresConnection($connection, $database, $prefix, $config),
            'sqlite' => new SQLiteConnection($connection, $database, $prefix, $config),
            'sqlsrv' => new SqlServerConnection($connection, $database, $prefix, $config),
            default => throw new InvalidArgumentException("Unsupported driver [{$driver}]."),
        };
    }
}
}

namespace Illuminate\Database\Connectors {
use Illuminate\Support\Arr;
use PDO;
class SqlServerConnector extends Connector implements ConnectorInterface
{
    protected $options = [PDO::ATTR_CASE => PDO::CASE_NATURAL, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_ORACLE_NULLS => PDO::NULL_NATURAL, PDO::ATTR_STRINGIFY_FETCHES => false];
    public function connect(array $config)
    {
        $options = $this->getOptions($config);
        $connection = $this->createConnection($this->getDsn($config), $config, $options);
        $this->configureIsolationLevel($connection, $config);
        return $connection;
    }
    protected function configureIsolationLevel($connection, array $config)
    {
        if (!isset($config['isolation_level'])) {
            return;
        }
        $connection->prepare("SET TRANSACTION ISOLATION LEVEL {$config['isolation_level']}")->execute();
    }
    protected function getDsn(array $config)
    {
        if ($this->prefersOdbc($config)) {
            return $this->getOdbcDsn($config);
        }
        if (in_array('sqlsrv', $this->getAvailableDrivers())) {
            return $this->getSqlSrvDsn($config);
        } else {
            return $this->getDblibDsn($config);
        }
    }
    protected function prefersOdbc(array $config)
    {
        return in_array('odbc', $this->getAvailableDrivers()) && ($config['odbc'] ?? null) === true;
    }
    protected function getDblibDsn(array $config)
    {
        return $this->buildConnectString('dblib', array_merge(['host' => $this->buildHostString($config, ':'), 'dbname' => $config['database']], Arr::only($config, ['appname', 'charset', 'version'])));
    }
    protected function getOdbcDsn(array $config)
    {
        return isset($config['odbc_datasource_name']) ? 'odbc:' . $config['odbc_datasource_name'] : '';
    }
    protected function getSqlSrvDsn(array $config)
    {
        $arguments = ['Server' => $this->buildHostString($config, ',')];
        if (isset($config['database'])) {
            $arguments['Database'] = $config['database'];
        }
        if (isset($config['readonly'])) {
            $arguments['ApplicationIntent'] = 'ReadOnly';
        }
        if (isset($config['pooling']) && $config['pooling'] === false) {
            $arguments['ConnectionPooling'] = '0';
        }
        if (isset($config['appname'])) {
            $arguments['APP'] = $config['appname'];
        }
        if (isset($config['encrypt'])) {
            $arguments['Encrypt'] = $config['encrypt'];
        }
        if (isset($config['trust_server_certificate'])) {
            $arguments['TrustServerCertificate'] = $config['trust_server_certificate'];
        }
        if (isset($config['multiple_active_result_sets']) && $config['multiple_active_result_sets'] === false) {
            $arguments['MultipleActiveResultSets'] = 'false';
        }
        if (isset($config['transaction_isolation'])) {
            $arguments['TransactionIsolation'] = $config['transaction_isolation'];
        }
        if (isset($config['multi_subnet_failover'])) {
            $arguments['MultiSubnetFailover'] = $config['multi_subnet_failover'];
        }
        if (isset($config['column_encryption'])) {
            $arguments['ColumnEncryption'] = $config['column_encryption'];
        }
        if (isset($config['key_store_authentication'])) {
            $arguments['KeyStoreAuthentication'] = $config['key_store_authentication'];
        }
        if (isset($config['key_store_principal_id'])) {
            $arguments['KeyStorePrincipalId'] = $config['key_store_principal_id'];
        }
        if (isset($config['key_store_secret'])) {
            $arguments['KeyStoreSecret'] = $config['key_store_secret'];
        }
        if (isset($config['login_timeout'])) {
            $arguments['LoginTimeout'] = $config['login_timeout'];
        }
        if (isset($config['authentication'])) {
            $arguments['Authentication'] = $config['authentication'];
        }
        return $this->buildConnectString('sqlsrv', $arguments);
    }
    protected function buildConnectString($driver, array $arguments)
    {
        return $driver . ':' . implode(';', array_map(function ($key) use ($arguments) {
            return sprintf('%s=%s', $key, $arguments[$key]);
        }, array_keys($arguments)));
    }
    protected function buildHostString(array $config, $separator)
    {
        if (empty($config['port'])) {
            return $config['host'];
        }
        return $config['host'] . $separator . $config['port'];
    }
    protected function getAvailableDrivers()
    {
        return PDO::getAvailableDrivers();
    }
}
}

namespace Illuminate\Database\Connectors {
use Illuminate\Database\Concerns\ParsesSearchPath;
use PDO;
class PostgresConnector extends Connector implements ConnectorInterface
{
    use ParsesSearchPath;
    protected $options = [PDO::ATTR_CASE => PDO::CASE_NATURAL, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_ORACLE_NULLS => PDO::NULL_NATURAL, PDO::ATTR_STRINGIFY_FETCHES => false];
    public function connect(array $config)
    {
        $connection = $this->createConnection($this->getDsn($config), $config, $this->getOptions($config));
        $this->configureIsolationLevel($connection, $config);
        $this->configureTimezone($connection, $config);
        $this->configureSearchPath($connection, $config);
        $this->configureSynchronousCommit($connection, $config);
        return $connection;
    }
    protected function configureIsolationLevel($connection, array $config)
    {
        if (isset($config['isolation_level'])) {
            $connection->prepare("set session characteristics as transaction isolation level {$config['isolation_level']}")->execute();
        }
    }
    protected function configureTimezone($connection, array $config)
    {
        if (isset($config['timezone'])) {
            $timezone = $config['timezone'];
            $connection->prepare("set time zone '{$timezone}'")->execute();
        }
    }
    protected function configureSearchPath($connection, $config)
    {
        if (isset($config['search_path']) || isset($config['schema'])) {
            $searchPath = $this->quoteSearchPath($this->parseSearchPath($config['search_path'] ?? $config['schema']));
            $connection->prepare("set search_path to {$searchPath}")->execute();
        }
    }
    protected function quoteSearchPath($searchPath)
    {
        return count($searchPath) === 1 ? '"' . $searchPath[0] . '"' : '"' . implode('", "', $searchPath) . '"';
    }
    protected function getDsn(array $config)
    {
        extract($config, EXTR_SKIP);
        $host = isset($host) ? "host={$host};" : '';
        $database = $connect_via_database ?? $database;
        $port = $connect_via_port ?? $port ?? null;
        $dsn = "pgsql:{$host}dbname='{$database}'";
        if (!is_null($port)) {
            $dsn .= ";port={$port}";
        }
        if (isset($charset)) {
            $dsn .= ";client_encoding='{$charset}'";
        }
        if (isset($application_name)) {
            $dsn .= ";application_name='" . str_replace("'", "\\'", $application_name) . "'";
        }
        return $this->addSslOptions($dsn, $config);
    }
    protected function addSslOptions($dsn, array $config)
    {
        foreach (['sslmode', 'sslcert', 'sslkey', 'sslrootcert'] as $option) {
            if (isset($config[$option])) {
                $dsn .= ";{$option}={$config[$option]}";
            }
        }
        return $dsn;
    }
    protected function configureSynchronousCommit($connection, array $config)
    {
        if (!isset($config['synchronous_commit'])) {
            return;
        }
        $connection->prepare("set synchronous_commit to '{$config['synchronous_commit']}'")->execute();
    }
}
}

namespace Illuminate\Database\Connectors {
interface ConnectorInterface
{
    public function connect(array $config);
}
}

namespace Illuminate\Database\Connectors {
use PDO;
class MySqlConnector extends Connector implements ConnectorInterface
{
    public function connect(array $config)
    {
        $dsn = $this->getDsn($config);
        $options = $this->getOptions($config);
        $connection = $this->createConnection($dsn, $config, $options);
        if (!empty($config['database'])) {
            $connection->exec("use `{$config['database']}`;");
        }
        $this->configureIsolationLevel($connection, $config);
        $this->configureEncoding($connection, $config);
        $this->configureTimezone($connection, $config);
        $this->setModes($connection, $config);
        return $connection;
    }
    protected function configureIsolationLevel($connection, array $config)
    {
        if (!isset($config['isolation_level'])) {
            return;
        }
        $connection->prepare("SET SESSION TRANSACTION ISOLATION LEVEL {$config['isolation_level']}")->execute();
    }
    protected function configureEncoding($connection, array $config)
    {
        if (!isset($config['charset'])) {
            return $connection;
        }
        $connection->prepare("set names '{$config['charset']}'" . $this->getCollation($config))->execute();
    }
    protected function getCollation(array $config)
    {
        return isset($config['collation']) ? " collate '{$config['collation']}'" : '';
    }
    protected function configureTimezone($connection, array $config)
    {
        if (isset($config['timezone'])) {
            $connection->prepare('set time_zone="' . $config['timezone'] . '"')->execute();
        }
    }
    protected function getDsn(array $config)
    {
        return $this->hasSocket($config) ? $this->getSocketDsn($config) : $this->getHostDsn($config);
    }
    protected function hasSocket(array $config)
    {
        return isset($config['unix_socket']) && !empty($config['unix_socket']);
    }
    protected function getSocketDsn(array $config)
    {
        return "mysql:unix_socket={$config['unix_socket']};dbname={$config['database']}";
    }
    protected function getHostDsn(array $config)
    {
        extract($config, EXTR_SKIP);
        return isset($port) ? "mysql:host={$host};port={$port};dbname={$database}" : "mysql:host={$host};dbname={$database}";
    }
    protected function setModes(PDO $connection, array $config)
    {
        if (isset($config['modes'])) {
            $this->setCustomModes($connection, $config);
        } elseif (isset($config['strict'])) {
            if ($config['strict']) {
                $connection->prepare($this->strictMode($connection, $config))->execute();
            } else {
                $connection->prepare("set session sql_mode='NO_ENGINE_SUBSTITUTION'")->execute();
            }
        }
    }
    protected function setCustomModes(PDO $connection, array $config)
    {
        $modes = implode(',', $config['modes']);
        $connection->prepare("set session sql_mode='{$modes}'")->execute();
    }
    protected function strictMode(PDO $connection, $config)
    {
        $version = $config['version'] ?? $connection->getAttribute(PDO::ATTR_SERVER_VERSION);
        if (version_compare($version, '8.0.11') >= 0) {
            return "set session sql_mode='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'";
        }
        return "set session sql_mode='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'";
    }
}
}

namespace Illuminate\Database\Connectors {
use Illuminate\Database\SQLiteDatabaseDoesNotExistException;
class SQLiteConnector extends Connector implements ConnectorInterface
{
    public function connect(array $config)
    {
        $options = $this->getOptions($config);
        if ($config['database'] === ':memory:') {
            return $this->createConnection('sqlite::memory:', $config, $options);
        }
        $path = realpath($config['database']);
        if ($path === false) {
            throw new SQLiteDatabaseDoesNotExistException($config['database']);
        }
        return $this->createConnection("sqlite:{$path}", $config, $options);
    }
}
}

namespace Illuminate\Database {
use Exception;
use Illuminate\Database\PDO\MySqlDriver;
use Illuminate\Database\Query\Grammars\MySqlGrammar as QueryGrammar;
use Illuminate\Database\Query\Processors\MySqlProcessor;
use Illuminate\Database\Schema\Grammars\MySqlGrammar as SchemaGrammar;
use Illuminate\Database\Schema\MySqlBuilder;
use Illuminate\Database\Schema\MySqlSchemaState;
use Illuminate\Filesystem\Filesystem;
use PDO;
class MySqlConnection extends Connection
{
    protected $lastInsertId;
    public function insert($query, $bindings = [], $sequence = null)
    {
        return $this->run($query, $bindings, function ($query, $bindings) use ($sequence) {
            if ($this->pretending()) {
                return true;
            }
            $statement = $this->getPdo()->prepare($query);
            $this->bindValues($statement, $this->prepareBindings($bindings));
            $this->recordsHaveBeenModified();
            $result = $statement->execute();
            $this->lastInsertId = $this->getPdo()->lastInsertId($sequence);
            return $result;
        });
    }
    protected function escapeBinary($value)
    {
        $hex = bin2hex($value);
        return "x'{$hex}'";
    }
    protected function isUniqueConstraintError(Exception $exception)
    {
        return boolval(preg_match('#Integrity constraint violation: 1062#i', $exception->getMessage()));
    }
    public function getLastInsertId()
    {
        return $this->lastInsertId;
    }
    public function isMaria()
    {
        return str_contains($this->getPdo()->getAttribute(PDO::ATTR_SERVER_VERSION), 'MariaDB');
    }
    protected function getDefaultQueryGrammar()
    {
        ($grammar = new QueryGrammar())->setConnection($this);
        return $this->withTablePrefix($grammar);
    }
    public function getSchemaBuilder()
    {
        if (is_null($this->schemaGrammar)) {
            $this->useDefaultSchemaGrammar();
        }
        return new MySqlBuilder($this);
    }
    protected function getDefaultSchemaGrammar()
    {
        ($grammar = new SchemaGrammar())->setConnection($this);
        return $this->withTablePrefix($grammar);
    }
    public function getSchemaState(?Filesystem $files = null, ?callable $processFactory = null)
    {
        return new MySqlSchemaState($this, $files, $processFactory);
    }
    protected function getDefaultPostProcessor()
    {
        return new MySqlProcessor();
    }
    protected function getDoctrineDriver()
    {
        return new MySqlDriver();
    }
}
}

namespace Illuminate\Database {
use Faker\Factory as FakerFactory;
use Faker\Generator as FakerGenerator;
use Illuminate\Contracts\Queue\EntityResolver;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\QueueEntityResolver;
use Illuminate\Support\ServiceProvider;
class DatabaseServiceProvider extends ServiceProvider
{
    protected static $fakers = [];
    public function boot()
    {
        Model::setConnectionResolver($this->app['db']);
        Model::setEventDispatcher($this->app['events']);
    }
    public function register()
    {
        Model::clearBootedModels();
        $this->registerConnectionServices();
        $this->registerEloquentFactory();
        $this->registerQueueableEntityResolver();
    }
    protected function registerConnectionServices()
    {
        $this->app->singleton('db.factory', function ($app) {
            return new ConnectionFactory($app);
        });
        $this->app->singleton('db', function ($app) {
            return new DatabaseManager($app, $app['db.factory']);
        });
        $this->app->bind('db.connection', function ($app) {
            return $app['db']->connection();
        });
        $this->app->bind('db.schema', function ($app) {
            return $app['db']->connection()->getSchemaBuilder();
        });
        $this->app->singleton('db.transactions', function ($app) {
            return new DatabaseTransactionsManager();
        });
    }
    protected function registerEloquentFactory()
    {
        $this->app->singleton(FakerGenerator::class, function ($app, $parameters) {
            $locale = $parameters['locale'] ?? $app['config']->get('app.faker_locale', 'en_US');
            if (!isset(static::$fakers[$locale])) {
                static::$fakers[$locale] = FakerFactory::create($locale);
            }
            static::$fakers[$locale]->unique(true);
            return static::$fakers[$locale];
        });
    }
    protected function registerQueueableEntityResolver()
    {
        $this->app->singleton(EntityResolver::class, function () {
            return new QueueEntityResolver();
        });
    }
}
}

namespace Illuminate\Database\Events {
abstract class ConnectionEvent
{
    public $connectionName;
    public $connection;
    public function __construct($connection)
    {
        $this->connection = $connection;
        $this->connectionName = $connection->getName();
    }
}
}

namespace Illuminate\Database\Events {
class TransactionCommitted extends ConnectionEvent
{
}
}

namespace Illuminate\Database\Events {
class TransactionBeginning extends ConnectionEvent
{
}
}

namespace Illuminate\Database\Events {
class TransactionRolledBack extends ConnectionEvent
{
}
}

namespace Illuminate\Database\Events {
class QueryExecuted
{
    public $sql;
    public $bindings;
    public $time;
    public $connection;
    public $connectionName;
    public function __construct($sql, $bindings, $time, $connection)
    {
        $this->sql = $sql;
        $this->time = $time;
        $this->bindings = $bindings;
        $this->connection = $connection;
        $this->connectionName = $connection->getName();
    }
}
}

namespace Illuminate\Database\Migrations {
use Doctrine\DBAL\Schema\SchemaException;
use Illuminate\Console\View\Components\BulletList;
use Illuminate\Console\View\Components\Error;
use Illuminate\Console\View\Components\Info;
use Illuminate\Console\View\Components\Task;
use Illuminate\Console\View\Components\TwoColumnDetail;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface as Resolver;
use Illuminate\Database\Events\MigrationEnded;
use Illuminate\Database\Events\MigrationsEnded;
use Illuminate\Database\Events\MigrationsStarted;
use Illuminate\Database\Events\MigrationStarted;
use Illuminate\Database\Events\NoPendingMigrations;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use ReflectionClass;
use Symfony\Component\Console\Output\OutputInterface;
class Migrator
{
    protected $events;
    protected $repository;
    protected $files;
    protected $resolver;
    protected $connection;
    protected $paths = [];
    protected static $requiredPathCache = [];
    protected $output;
    public function __construct(MigrationRepositoryInterface $repository, Resolver $resolver, Filesystem $files, ?Dispatcher $dispatcher = null)
    {
        $this->files = $files;
        $this->events = $dispatcher;
        $this->resolver = $resolver;
        $this->repository = $repository;
    }
    public function run($paths = [], array $options = [])
    {
        $files = $this->getMigrationFiles($paths);
        $this->requireFiles($migrations = $this->pendingMigrations($files, $this->repository->getRan()));
        $this->runPending($migrations, $options);
        return $migrations;
    }
    protected function pendingMigrations($files, $ran)
    {
        return Collection::make($files)->reject(function ($file) use ($ran) {
            return in_array($this->getMigrationName($file), $ran);
        })->values()->all();
    }
    public function runPending(array $migrations, array $options = [])
    {
        if (count($migrations) === 0) {
            $this->fireMigrationEvent(new NoPendingMigrations('up'));
            $this->write(Info::class, 'Nothing to migrate');
            return;
        }
        $batch = $this->repository->getNextBatchNumber();
        $pretend = $options['pretend'] ?? false;
        $step = $options['step'] ?? false;
        $this->fireMigrationEvent(new MigrationsStarted('up'));
        $this->write(Info::class, 'Running migrations.');
        foreach ($migrations as $file) {
            $this->runUp($file, $batch, $pretend);
            if ($step) {
                $batch++;
            }
        }
        $this->fireMigrationEvent(new MigrationsEnded('up'));
        if ($this->output) {
            $this->output->writeln('');
        }
    }
    protected function runUp($file, $batch, $pretend)
    {
        $migration = $this->resolvePath($file);
        $name = $this->getMigrationName($file);
        if ($pretend) {
            return $this->pretendToRun($migration, 'up');
        }
        $this->write(Task::class, $name, fn() => $this->runMigration($migration, 'up'));
        $this->repository->log($name, $batch);
    }
    public function rollback($paths = [], array $options = [])
    {
        $migrations = $this->getMigrationsForRollback($options);
        if (count($migrations) === 0) {
            $this->fireMigrationEvent(new NoPendingMigrations('down'));
            $this->write(Info::class, 'Nothing to rollback.');
            return [];
        }
        return tap($this->rollbackMigrations($migrations, $paths, $options), function () {
            if ($this->output) {
                $this->output->writeln('');
            }
        });
    }
    protected function getMigrationsForRollback(array $options)
    {
        if (($steps = $options['step'] ?? 0) > 0) {
            return $this->repository->getMigrations($steps);
        }
        if (($batch = $options['batch'] ?? 0) > 0) {
            return $this->repository->getMigrationsByBatch($batch);
        }
        return $this->repository->getLast();
    }
    protected function rollbackMigrations(array $migrations, $paths, array $options)
    {
        $rolledBack = [];
        $this->requireFiles($files = $this->getMigrationFiles($paths));
        $this->fireMigrationEvent(new MigrationsStarted('down'));
        $this->write(Info::class, 'Rolling back migrations.');
        foreach ($migrations as $migration) {
            $migration = (object) $migration;
            if (!$file = Arr::get($files, $migration->migration)) {
                $this->write(TwoColumnDetail::class, $migration->migration, '<fg=yellow;options=bold>Migration not found</>');
                continue;
            }
            $rolledBack[] = $file;
            $this->runDown($file, $migration, $options['pretend'] ?? false);
        }
        $this->fireMigrationEvent(new MigrationsEnded('down'));
        return $rolledBack;
    }
    public function reset($paths = [], $pretend = false)
    {
        $migrations = array_reverse($this->repository->getRan());
        if (count($migrations) === 0) {
            $this->write(Info::class, 'Nothing to rollback.');
            return [];
        }
        return tap($this->resetMigrations($migrations, Arr::wrap($paths), $pretend), function () {
            if ($this->output) {
                $this->output->writeln('');
            }
        });
    }
    protected function resetMigrations(array $migrations, array $paths, $pretend = false)
    {
        $migrations = collect($migrations)->map(function ($m) {
            return (object) ['migration' => $m];
        })->all();
        return $this->rollbackMigrations($migrations, $paths, compact('pretend'));
    }
    protected function runDown($file, $migration, $pretend)
    {
        $instance = $this->resolvePath($file);
        $name = $this->getMigrationName($file);
        if ($pretend) {
            return $this->pretendToRun($instance, 'down');
        }
        $this->write(Task::class, $name, fn() => $this->runMigration($instance, 'down'));
        $this->repository->delete($migration);
    }
    protected function runMigration($migration, $method)
    {
        $connection = $this->resolveConnection($migration->getConnection());
        $callback = function () use ($connection, $migration, $method) {
            if (method_exists($migration, $method)) {
                $this->fireMigrationEvent(new MigrationStarted($migration, $method));
                $this->runMethod($connection, $migration, $method);
                $this->fireMigrationEvent(new MigrationEnded($migration, $method));
            }
        };
        $this->getSchemaGrammar($connection)->supportsSchemaTransactions() && $migration->withinTransaction ? $connection->transaction($callback) : $callback();
    }
    protected function pretendToRun($migration, $method)
    {
        try {
            $name = get_class($migration);
            $reflectionClass = new ReflectionClass($migration);
            if ($reflectionClass->isAnonymous()) {
                $name = $this->getMigrationName($reflectionClass->getFileName());
            }
            $this->write(TwoColumnDetail::class, $name);
            $this->write(BulletList::class, collect($this->getQueries($migration, $method))->map(function ($query) {
                return $query['query'];
            }));
        } catch (SchemaException) {
            $name = get_class($migration);
            $this->write(Error::class, sprintf('[%s] failed to dump queries. This may be due to changing database columns using Doctrine, which is not supported while pretending to run migrations.', $name));
        }
    }
    protected function getQueries($migration, $method)
    {
        $db = $this->resolveConnection($migration->getConnection());
        return $db->pretend(function () use ($db, $migration, $method) {
            if (method_exists($migration, $method)) {
                $this->runMethod($db, $migration, $method);
            }
        });
    }
    protected function runMethod($connection, $migration, $method)
    {
        $previousConnection = $this->resolver->getDefaultConnection();
        try {
            $this->resolver->setDefaultConnection($connection->getName());
            $migration->{$method}();
        } finally {
            $this->resolver->setDefaultConnection($previousConnection);
        }
    }
    public function resolve($file)
    {
        $class = $this->getMigrationClass($file);
        return new $class();
    }
    protected function resolvePath(string $path)
    {
        $class = $this->getMigrationClass($this->getMigrationName($path));
        if (class_exists($class) && realpath($path) == (new ReflectionClass($class))->getFileName()) {
            return new $class();
        }
        $migration = static::$requiredPathCache[$path] ??= $this->files->getRequire($path);
        if (is_object($migration)) {
            return method_exists($migration, '__construct') ? $this->files->getRequire($path) : clone $migration;
        }
        return new $class();
    }
    protected function getMigrationClass(string $migrationName): string
    {
        return Str::studly(implode('_', array_slice(explode('_', $migrationName), 4)));
    }
    public function getMigrationFiles($paths)
    {
        return Collection::make($paths)->flatMap(function ($path) {
            return str_ends_with($path, '.php') ? [$path] : $this->files->glob($path . '/*_*.php');
        })->filter()->values()->keyBy(function ($file) {
            return $this->getMigrationName($file);
        })->sortBy(function ($file, $key) {
            return $key;
        })->all();
    }
    public function requireFiles(array $files)
    {
        foreach ($files as $file) {
            $this->files->requireOnce($file);
        }
    }
    public function getMigrationName($path)
    {
        return str_replace('.php', '', basename($path));
    }
    public function path($path)
    {
        $this->paths = array_unique(array_merge($this->paths, [$path]));
    }
    public function paths()
    {
        return $this->paths;
    }
    public function getConnection()
    {
        return $this->connection;
    }
    public function usingConnection($name, callable $callback)
    {
        $previousConnection = $this->resolver->getDefaultConnection();
        $this->setConnection($name);
        return tap($callback(), function () use ($previousConnection) {
            $this->setConnection($previousConnection);
        });
    }
    public function setConnection($name)
    {
        if (!is_null($name)) {
            $this->resolver->setDefaultConnection($name);
        }
        $this->repository->setSource($name);
        $this->connection = $name;
    }
    public function resolveConnection($connection)
    {
        return $this->resolver->connection($connection ?: $this->connection);
    }
    protected function getSchemaGrammar($connection)
    {
        if (is_null($grammar = $connection->getSchemaGrammar())) {
            $connection->useDefaultSchemaGrammar();
            $grammar = $connection->getSchemaGrammar();
        }
        return $grammar;
    }
    public function getRepository()
    {
        return $this->repository;
    }
    public function repositoryExists()
    {
        return $this->repository->repositoryExists();
    }
    public function hasRunAnyMigrations()
    {
        return $this->repositoryExists() && count($this->repository->getRan()) > 0;
    }
    public function deleteRepository()
    {
        $this->repository->deleteRepository();
    }
    public function getFilesystem()
    {
        return $this->files;
    }
    public function setOutput(OutputInterface $output)
    {
        $this->output = $output;
        return $this;
    }
    protected function write($component, ...$arguments)
    {
        if ($this->output && class_exists($component)) {
            (new $component($this->output))->render(...$arguments);
        } else {
            foreach ($arguments as $argument) {
                if (is_callable($argument)) {
                    $argument();
                }
            }
        }
    }
    public function fireMigrationEvent($event)
    {
        if ($this->events) {
            $this->events->dispatch($event);
        }
    }
}
}

namespace Illuminate\Database\Migrations {
abstract class Migration
{
    protected $connection;
    public $withinTransaction = true;
    public function getConnection()
    {
        return $this->connection;
    }
}
}

namespace Illuminate\Database\Migrations {
interface MigrationRepositoryInterface
{
    public function getRan();
    public function getMigrations($steps);
    public function getMigrationsByBatch($batch);
    public function getLast();
    public function getMigrationBatches();
    public function log($file, $batch);
    public function delete($migration);
    public function getNextBatchNumber();
    public function createRepository();
    public function repositoryExists();
    public function deleteRepository();
    public function setSource($name);
}
}

namespace Illuminate\Database\Migrations {
use Illuminate\Database\ConnectionResolverInterface as Resolver;
class DatabaseMigrationRepository implements MigrationRepositoryInterface
{
    protected $resolver;
    protected $table;
    protected $connection;
    public function __construct(Resolver $resolver, $table)
    {
        $this->table = $table;
        $this->resolver = $resolver;
    }
    public function getRan()
    {
        return $this->table()->orderBy('batch', 'asc')->orderBy('migration', 'asc')->pluck('migration')->all();
    }
    public function getMigrations($steps)
    {
        $query = $this->table()->where('batch', '>=', '1');
        return $query->orderBy('batch', 'desc')->orderBy('migration', 'desc')->take($steps)->get()->all();
    }
    public function getMigrationsByBatch($batch)
    {
        return $this->table()->where('batch', $batch)->orderBy('migration', 'desc')->get()->all();
    }
    public function getLast()
    {
        $query = $this->table()->where('batch', $this->getLastBatchNumber());
        return $query->orderBy('migration', 'desc')->get()->all();
    }
    public function getMigrationBatches()
    {
        return $this->table()->orderBy('batch', 'asc')->orderBy('migration', 'asc')->pluck('batch', 'migration')->all();
    }
    public function log($file, $batch)
    {
        $record = ['migration' => $file, 'batch' => $batch];
        $this->table()->insert($record);
    }
    public function delete($migration)
    {
        $this->table()->where('migration', $migration->migration)->delete();
    }
    public function getNextBatchNumber()
    {
        return $this->getLastBatchNumber() + 1;
    }
    public function getLastBatchNumber()
    {
        return $this->table()->max('batch');
    }
    public function createRepository()
    {
        $schema = $this->getConnection()->getSchemaBuilder();
        $schema->create($this->table, function ($table) {
            $table->increments('id');
            $table->string('migration');
            $table->integer('batch');
        });
    }
    public function repositoryExists()
    {
        $schema = $this->getConnection()->getSchemaBuilder();
        return $schema->hasTable($this->table);
    }
    public function deleteRepository()
    {
        $schema = $this->getConnection()->getSchemaBuilder();
        $schema->drop($this->table);
    }
    protected function table()
    {
        return $this->getConnection()->table($this->table)->useWritePdo();
    }
    public function getConnectionResolver()
    {
        return $this->resolver;
    }
    public function getConnection()
    {
        return $this->resolver->connection($this->connection);
    }
    public function setSource($name)
    {
        $this->connection = $name;
    }
}
}

namespace Illuminate\Database\Schema {
use BadMethodCallException;
use Closure;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Schema\Grammars\Grammar;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Support\Fluent;
use Illuminate\Support\Traits\Macroable;
class Blueprint
{
    use Macroable;
    protected $table;
    protected $prefix;
    protected $columns = [];
    protected $commands = [];
    public $engine;
    public $charset;
    public $collation;
    public $temporary = false;
    public $after;
    public function __construct($table, ?Closure $callback = null, $prefix = '')
    {
        $this->table = $table;
        $this->prefix = $prefix;
        if (!is_null($callback)) {
            $callback($this);
        }
    }
    public function build(Connection $connection, Grammar $grammar)
    {
        foreach ($this->toSql($connection, $grammar) as $statement) {
            $connection->statement($statement);
        }
    }
    public function toSql(Connection $connection, Grammar $grammar)
    {
        $this->addImpliedCommands($connection, $grammar);
        $statements = [];
        $this->ensureCommandsAreValid($connection);
        foreach ($this->commands as $command) {
            if ($command->shouldBeSkipped) {
                continue;
            }
            $method = 'compile' . ucfirst($command->name);
            if (method_exists($grammar, $method) || $grammar::hasMacro($method)) {
                if (!is_null($sql = $grammar->{$method}($this, $command, $connection))) {
                    $statements = array_merge($statements, (array) $sql);
                }
            }
        }
        return $statements;
    }
    protected function ensureCommandsAreValid(Connection $connection)
    {
        if ($connection instanceof SQLiteConnection) {
            if ($this->commandsNamed(['dropColumn', 'renameColumn'])->count() > 1 && !$connection->usingNativeSchemaOperations()) {
                throw new BadMethodCallException("SQLite doesn't support multiple calls to dropColumn / renameColumn in a single modification.");
            }
            if ($this->commandsNamed(['dropForeign'])->count() > 0) {
                throw new BadMethodCallException("SQLite doesn't support dropping foreign keys (you would need to re-create the table).");
            }
        }
    }
    protected function commandsNamed(array $names)
    {
        return collect($this->commands)->filter(function ($command) use ($names) {
            return in_array($command->name, $names);
        });
    }
    protected function addImpliedCommands(Connection $connection, Grammar $grammar)
    {
        if (count($this->getAddedColumns()) > 0 && !$this->creating()) {
            array_unshift($this->commands, $this->createCommand('add'));
        }
        if (count($this->getChangedColumns()) > 0 && !$this->creating()) {
            array_unshift($this->commands, $this->createCommand('change'));
        }
        $this->addFluentIndexes();
        $this->addFluentCommands($connection, $grammar);
    }
    protected function addFluentIndexes()
    {
        foreach ($this->columns as $column) {
            foreach (['primary', 'unique', 'index', 'fulltext', 'fullText', 'spatialIndex'] as $index) {
                if ($column->{$index} === true) {
                    $this->{$index}($column->name);
                    $column->{$index} = null;
                    continue 2;
                } elseif ($column->{$index} === false && $column->change) {
                    $this->{'drop' . ucfirst($index)}([$column->name]);
                    $column->{$index} = null;
                    continue 2;
                } elseif (isset($column->{$index})) {
                    $this->{$index}($column->name, $column->{$index});
                    $column->{$index} = null;
                    continue 2;
                }
            }
        }
    }
    public function addFluentCommands(Connection $connection, Grammar $grammar)
    {
        foreach ($this->columns as $column) {
            if ($column->change && !$connection->usingNativeSchemaOperations()) {
                continue;
            }
            foreach ($grammar->getFluentCommands() as $commandName) {
                $this->addCommand($commandName, compact('column'));
            }
        }
    }
    public function creating()
    {
        return collect($this->commands)->contains(function ($command) {
            return $command->name === 'create';
        });
    }
    public function create()
    {
        return $this->addCommand('create');
    }
    public function engine($engine)
    {
        $this->engine = $engine;
    }
    public function innoDb()
    {
        $this->engine('InnoDB');
    }
    public function charset($charset)
    {
        $this->charset = $charset;
    }
    public function collation($collation)
    {
        $this->collation = $collation;
    }
    public function temporary()
    {
        $this->temporary = true;
    }
    public function drop()
    {
        return $this->addCommand('drop');
    }
    public function dropIfExists()
    {
        return $this->addCommand('dropIfExists');
    }
    public function dropColumn($columns)
    {
        $columns = is_array($columns) ? $columns : func_get_args();
        return $this->addCommand('dropColumn', compact('columns'));
    }
    public function renameColumn($from, $to)
    {
        return $this->addCommand('renameColumn', compact('from', 'to'));
    }
    public function dropPrimary($index = null)
    {
        return $this->dropIndexCommand('dropPrimary', 'primary', $index);
    }
    public function dropUnique($index)
    {
        return $this->dropIndexCommand('dropUnique', 'unique', $index);
    }
    public function dropIndex($index)
    {
        return $this->dropIndexCommand('dropIndex', 'index', $index);
    }
    public function dropFullText($index)
    {
        return $this->dropIndexCommand('dropFullText', 'fulltext', $index);
    }
    public function dropSpatialIndex($index)
    {
        return $this->dropIndexCommand('dropSpatialIndex', 'spatialIndex', $index);
    }
    public function dropForeign($index)
    {
        return $this->dropIndexCommand('dropForeign', 'foreign', $index);
    }
    public function dropConstrainedForeignId($column)
    {
        $this->dropForeign([$column]);
        return $this->dropColumn($column);
    }
    public function dropForeignIdFor($model, $column = null)
    {
        if (is_string($model)) {
            $model = new $model();
        }
        return $this->dropForeign([$column ?: $model->getForeignKey()]);
    }
    public function dropConstrainedForeignIdFor($model, $column = null)
    {
        if (is_string($model)) {
            $model = new $model();
        }
        return $this->dropConstrainedForeignId($column ?: $model->getForeignKey());
    }
    public function renameIndex($from, $to)
    {
        return $this->addCommand('renameIndex', compact('from', 'to'));
    }
    public function dropTimestamps()
    {
        $this->dropColumn('created_at', 'updated_at');
    }
    public function dropTimestampsTz()
    {
        $this->dropTimestamps();
    }
    public function dropSoftDeletes($column = 'deleted_at')
    {
        $this->dropColumn($column);
    }
    public function dropSoftDeletesTz($column = 'deleted_at')
    {
        $this->dropSoftDeletes($column);
    }
    public function dropRememberToken()
    {
        $this->dropColumn('remember_token');
    }
    public function dropMorphs($name, $indexName = null)
    {
        $this->dropIndex($indexName ?: $this->createIndexName('index', ["{$name}_type", "{$name}_id"]));
        $this->dropColumn("{$name}_type", "{$name}_id");
    }
    public function rename($to)
    {
        return $this->addCommand('rename', compact('to'));
    }
    public function primary($columns, $name = null, $algorithm = null)
    {
        return $this->indexCommand('primary', $columns, $name, $algorithm);
    }
    public function unique($columns, $name = null, $algorithm = null)
    {
        return $this->indexCommand('unique', $columns, $name, $algorithm);
    }
    public function index($columns, $name = null, $algorithm = null)
    {
        return $this->indexCommand('index', $columns, $name, $algorithm);
    }
    public function fullText($columns, $name = null, $algorithm = null)
    {
        return $this->indexCommand('fulltext', $columns, $name, $algorithm);
    }
    public function spatialIndex($columns, $name = null)
    {
        return $this->indexCommand('spatialIndex', $columns, $name);
    }
    public function rawIndex($expression, $name)
    {
        return $this->index([new Expression($expression)], $name);
    }
    public function foreign($columns, $name = null)
    {
        $command = new ForeignKeyDefinition($this->indexCommand('foreign', $columns, $name)->getAttributes());
        $this->commands[count($this->commands) - 1] = $command;
        return $command;
    }
    public function id($column = 'id')
    {
        return $this->bigIncrements($column);
    }
    public function increments($column)
    {
        return $this->unsignedInteger($column, true);
    }
    public function integerIncrements($column)
    {
        return $this->unsignedInteger($column, true);
    }
    public function tinyIncrements($column)
    {
        return $this->unsignedTinyInteger($column, true);
    }
    public function smallIncrements($column)
    {
        return $this->unsignedSmallInteger($column, true);
    }
    public function mediumIncrements($column)
    {
        return $this->unsignedMediumInteger($column, true);
    }
    public function bigIncrements($column)
    {
        return $this->unsignedBigInteger($column, true);
    }
    public function char($column, $length = null)
    {
        $length = !is_null($length) ? $length : Builder::$defaultStringLength;
        return $this->addColumn('char', $column, compact('length'));
    }
    public function string($column, $length = null)
    {
        $length = $length ?: Builder::$defaultStringLength;
        return $this->addColumn('string', $column, compact('length'));
    }
    public function tinyText($column)
    {
        return $this->addColumn('tinyText', $column);
    }
    public function text($column)
    {
        return $this->addColumn('text', $column);
    }
    public function mediumText($column)
    {
        return $this->addColumn('mediumText', $column);
    }
    public function longText($column)
    {
        return $this->addColumn('longText', $column);
    }
    public function integer($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('integer', $column, compact('autoIncrement', 'unsigned'));
    }
    public function tinyInteger($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('tinyInteger', $column, compact('autoIncrement', 'unsigned'));
    }
    public function smallInteger($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('smallInteger', $column, compact('autoIncrement', 'unsigned'));
    }
    public function mediumInteger($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('mediumInteger', $column, compact('autoIncrement', 'unsigned'));
    }
    public function bigInteger($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('bigInteger', $column, compact('autoIncrement', 'unsigned'));
    }
    public function unsignedInteger($column, $autoIncrement = false)
    {
        return $this->integer($column, $autoIncrement, true);
    }
    public function unsignedTinyInteger($column, $autoIncrement = false)
    {
        return $this->tinyInteger($column, $autoIncrement, true);
    }
    public function unsignedSmallInteger($column, $autoIncrement = false)
    {
        return $this->smallInteger($column, $autoIncrement, true);
    }
    public function unsignedMediumInteger($column, $autoIncrement = false)
    {
        return $this->mediumInteger($column, $autoIncrement, true);
    }
    public function unsignedBigInteger($column, $autoIncrement = false)
    {
        return $this->bigInteger($column, $autoIncrement, true);
    }
    public function foreignId($column)
    {
        return $this->addColumnDefinition(new ForeignIdColumnDefinition($this, ['type' => 'bigInteger', 'name' => $column, 'autoIncrement' => false, 'unsigned' => true]));
    }
    public function foreignIdFor($model, $column = null)
    {
        if (is_string($model)) {
            $model = new $model();
        }
        $column = $column ?: $model->getForeignKey();
        if ($model->getKeyType() === 'int' && $model->getIncrementing()) {
            return $this->foreignId($column);
        }
        $modelTraits = class_uses_recursive($model);
        if (in_array(HasUlids::class, $modelTraits, true)) {
            return $this->foreignUlid($column);
        }
        return $this->foreignUuid($column);
    }
    public function float($column, $total = 8, $places = 2, $unsigned = false)
    {
        return $this->addColumn('float', $column, compact('total', 'places', 'unsigned'));
    }
    public function double($column, $total = null, $places = null, $unsigned = false)
    {
        return $this->addColumn('double', $column, compact('total', 'places', 'unsigned'));
    }
    public function decimal($column, $total = 8, $places = 2, $unsigned = false)
    {
        return $this->addColumn('decimal', $column, compact('total', 'places', 'unsigned'));
    }
    public function unsignedFloat($column, $total = 8, $places = 2)
    {
        return $this->float($column, $total, $places, true);
    }
    public function unsignedDouble($column, $total = null, $places = null)
    {
        return $this->double($column, $total, $places, true);
    }
    public function unsignedDecimal($column, $total = 8, $places = 2)
    {
        return $this->decimal($column, $total, $places, true);
    }
    public function boolean($column)
    {
        return $this->addColumn('boolean', $column);
    }
    public function enum($column, array $allowed)
    {
        return $this->addColumn('enum', $column, compact('allowed'));
    }
    public function set($column, array $allowed)
    {
        return $this->addColumn('set', $column, compact('allowed'));
    }
    public function json($column)
    {
        return $this->addColumn('json', $column);
    }
    public function jsonb($column)
    {
        return $this->addColumn('jsonb', $column);
    }
    public function date($column)
    {
        return $this->addColumn('date', $column);
    }
    public function dateTime($column, $precision = 0)
    {
        return $this->addColumn('dateTime', $column, compact('precision'));
    }
    public function dateTimeTz($column, $precision = 0)
    {
        return $this->addColumn('dateTimeTz', $column, compact('precision'));
    }
    public function time($column, $precision = 0)
    {
        return $this->addColumn('time', $column, compact('precision'));
    }
    public function timeTz($column, $precision = 0)
    {
        return $this->addColumn('timeTz', $column, compact('precision'));
    }
    public function timestamp($column, $precision = 0)
    {
        return $this->addColumn('timestamp', $column, compact('precision'));
    }
    public function timestampTz($column, $precision = 0)
    {
        return $this->addColumn('timestampTz', $column, compact('precision'));
    }
    public function timestamps($precision = 0)
    {
        $this->timestamp('created_at', $precision)->nullable();
        $this->timestamp('updated_at', $precision)->nullable();
    }
    public function nullableTimestamps($precision = 0)
    {
        $this->timestamps($precision);
    }
    public function timestampsTz($precision = 0)
    {
        $this->timestampTz('created_at', $precision)->nullable();
        $this->timestampTz('updated_at', $precision)->nullable();
    }
    public function datetimes($precision = 0)
    {
        $this->datetime('created_at', $precision)->nullable();
        $this->datetime('updated_at', $precision)->nullable();
    }
    public function softDeletes($column = 'deleted_at', $precision = 0)
    {
        return $this->timestamp($column, $precision)->nullable();
    }
    public function softDeletesTz($column = 'deleted_at', $precision = 0)
    {
        return $this->timestampTz($column, $precision)->nullable();
    }
    public function softDeletesDatetime($column = 'deleted_at', $precision = 0)
    {
        return $this->datetime($column, $precision)->nullable();
    }
    public function year($column)
    {
        return $this->addColumn('year', $column);
    }
    public function binary($column)
    {
        return $this->addColumn('binary', $column);
    }
    public function uuid($column = 'uuid')
    {
        return $this->addColumn('uuid', $column);
    }
    public function foreignUuid($column)
    {
        return $this->addColumnDefinition(new ForeignIdColumnDefinition($this, ['type' => 'uuid', 'name' => $column]));
    }
    public function ulid($column = 'ulid', $length = 26)
    {
        return $this->char($column, $length);
    }
    public function foreignUlid($column, $length = 26)
    {
        return $this->addColumnDefinition(new ForeignIdColumnDefinition($this, ['type' => 'char', 'name' => $column, 'length' => $length]));
    }
    public function ipAddress($column = 'ip_address')
    {
        return $this->addColumn('ipAddress', $column);
    }
    public function macAddress($column = 'mac_address')
    {
        return $this->addColumn('macAddress', $column);
    }
    public function geometry($column)
    {
        return $this->addColumn('geometry', $column);
    }
    public function point($column, $srid = null)
    {
        return $this->addColumn('point', $column, compact('srid'));
    }
    public function lineString($column)
    {
        return $this->addColumn('linestring', $column);
    }
    public function polygon($column)
    {
        return $this->addColumn('polygon', $column);
    }
    public function geometryCollection($column)
    {
        return $this->addColumn('geometrycollection', $column);
    }
    public function multiPoint($column)
    {
        return $this->addColumn('multipoint', $column);
    }
    public function multiLineString($column)
    {
        return $this->addColumn('multilinestring', $column);
    }
    public function multiPolygon($column)
    {
        return $this->addColumn('multipolygon', $column);
    }
    public function multiPolygonZ($column)
    {
        return $this->addColumn('multipolygonz', $column);
    }
    public function computed($column, $expression)
    {
        return $this->addColumn('computed', $column, compact('expression'));
    }
    public function morphs($name, $indexName = null)
    {
        if (Builder::$defaultMorphKeyType === 'uuid') {
            $this->uuidMorphs($name, $indexName);
        } elseif (Builder::$defaultMorphKeyType === 'ulid') {
            $this->ulidMorphs($name, $indexName);
        } else {
            $this->numericMorphs($name, $indexName);
        }
    }
    public function nullableMorphs($name, $indexName = null)
    {
        if (Builder::$defaultMorphKeyType === 'uuid') {
            $this->nullableUuidMorphs($name, $indexName);
        } elseif (Builder::$defaultMorphKeyType === 'ulid') {
            $this->nullableUlidMorphs($name, $indexName);
        } else {
            $this->nullableNumericMorphs($name, $indexName);
        }
    }
    public function numericMorphs($name, $indexName = null)
    {
        $this->string("{$name}_type");
        $this->unsignedBigInteger("{$name}_id");
        $this->index(["{$name}_type", "{$name}_id"], $indexName);
    }
    public function nullableNumericMorphs($name, $indexName = null)
    {
        $this->string("{$name}_type")->nullable();
        $this->unsignedBigInteger("{$name}_id")->nullable();
        $this->index(["{$name}_type", "{$name}_id"], $indexName);
    }
    public function uuidMorphs($name, $indexName = null)
    {
        $this->string("{$name}_type");
        $this->uuid("{$name}_id");
        $this->index(["{$name}_type", "{$name}_id"], $indexName);
    }
    public function nullableUuidMorphs($name, $indexName = null)
    {
        $this->string("{$name}_type")->nullable();
        $this->uuid("{$name}_id")->nullable();
        $this->index(["{$name}_type", "{$name}_id"], $indexName);
    }
    public function ulidMorphs($name, $indexName = null)
    {
        $this->string("{$name}_type");
        $this->ulid("{$name}_id");
        $this->index(["{$name}_type", "{$name}_id"], $indexName);
    }
    public function nullableUlidMorphs($name, $indexName = null)
    {
        $this->string("{$name}_type")->nullable();
        $this->ulid("{$name}_id")->nullable();
        $this->index(["{$name}_type", "{$name}_id"], $indexName);
    }
    public function rememberToken()
    {
        return $this->string('remember_token', 100)->nullable();
    }
    public function comment($comment)
    {
        return $this->addCommand('tableComment', compact('comment'));
    }
    protected function indexCommand($type, $columns, $index, $algorithm = null)
    {
        $columns = (array) $columns;
        $index = $index ?: $this->createIndexName($type, $columns);
        return $this->addCommand($type, compact('index', 'columns', 'algorithm'));
    }
    protected function dropIndexCommand($command, $type, $index)
    {
        $columns = [];
        if (is_array($index)) {
            $index = $this->createIndexName($type, $columns = $index);
        }
        return $this->indexCommand($command, $columns, $index);
    }
    protected function createIndexName($type, array $columns)
    {
        $index = strtolower($this->prefix . $this->table . '_' . implode('_', $columns) . '_' . $type);
        return str_replace(['-', '.'], '_', $index);
    }
    public function addColumn($type, $name, array $parameters = [])
    {
        return $this->addColumnDefinition(new ColumnDefinition(array_merge(compact('type', 'name'), $parameters)));
    }
    protected function addColumnDefinition($definition)
    {
        $this->columns[] = $definition;
        if ($this->after) {
            $definition->after($this->after);
            $this->after = $definition->name;
        }
        return $definition;
    }
    public function after($column, Closure $callback)
    {
        $this->after = $column;
        $callback($this);
        $this->after = null;
    }
    public function removeColumn($name)
    {
        $this->columns = array_values(array_filter($this->columns, function ($c) use ($name) {
            return $c['name'] != $name;
        }));
        return $this;
    }
    protected function addCommand($name, array $parameters = [])
    {
        $this->commands[] = $command = $this->createCommand($name, $parameters);
        return $command;
    }
    protected function createCommand($name, array $parameters = [])
    {
        return new Fluent(array_merge(compact('name'), $parameters));
    }
    public function getTable()
    {
        return $this->table;
    }
    public function getPrefix()
    {
        return $this->prefix;
    }
    public function getColumns()
    {
        return $this->columns;
    }
    public function getCommands()
    {
        return $this->commands;
    }
    public function getAddedColumns()
    {
        return array_filter($this->columns, function ($column) {
            return !$column->change;
        });
    }
    public function getChangedColumns()
    {
        return array_filter($this->columns, function ($column) {
            return (bool) $column->change;
        });
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use BackedEnum;
use Doctrine\DBAL\Schema\AbstractSchemaManager as SchemaManager;
use Doctrine\DBAL\Schema\TableDiff;
use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Concerns\CompilesJsonPaths;
use Illuminate\Database\Connection;
use Illuminate\Database\Grammar as BaseGrammar;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Fluent;
use LogicException;
use RuntimeException;
abstract class Grammar extends BaseGrammar
{
    use CompilesJsonPaths;
    protected $modifiers = [];
    protected $transactions = false;
    protected $fluentCommands = [];
    public function compileCreateDatabase($name, $connection)
    {
        throw new LogicException('This database driver does not support creating databases.');
    }
    public function compileDropDatabaseIfExists($name)
    {
        throw new LogicException('This database driver does not support dropping databases.');
    }
    public function compileRenameColumn(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        return RenameColumn::compile($this, $blueprint, $command, $connection);
    }
    public function compileChange(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        return ChangeColumn::compile($this, $blueprint, $command, $connection);
    }
    public function compileFulltext(Blueprint $blueprint, Fluent $command)
    {
        throw new RuntimeException('This database driver does not support fulltext index creation.');
    }
    public function compileDropFullText(Blueprint $blueprint, Fluent $command)
    {
        throw new RuntimeException('This database driver does not support fulltext index removal.');
    }
    public function compileForeign(Blueprint $blueprint, Fluent $command)
    {
        $sql = sprintf('alter table %s add constraint %s ', $this->wrapTable($blueprint), $this->wrap($command->index));
        $sql .= sprintf('foreign key (%s) references %s (%s)', $this->columnize($command->columns), $this->wrapTable($command->on), $this->columnize((array) $command->references));
        if (!is_null($command->onDelete)) {
            $sql .= " on delete {$command->onDelete}";
        }
        if (!is_null($command->onUpdate)) {
            $sql .= " on update {$command->onUpdate}";
        }
        return $sql;
    }
    protected function getColumns(Blueprint $blueprint)
    {
        $columns = [];
        foreach ($blueprint->getAddedColumns() as $column) {
            $sql = $this->wrap($column) . ' ' . $this->getType($column);
            $columns[] = $this->addModifiers($sql, $blueprint, $column);
        }
        return $columns;
    }
    protected function getType(Fluent $column)
    {
        return $this->{'type' . ucfirst($column->type)}($column);
    }
    protected function typeComputed(Fluent $column)
    {
        throw new RuntimeException('This database driver does not support the computed type.');
    }
    protected function addModifiers($sql, Blueprint $blueprint, Fluent $column)
    {
        foreach ($this->modifiers as $modifier) {
            if (method_exists($this, $method = "modify{$modifier}")) {
                $sql .= $this->{$method}($blueprint, $column);
            }
        }
        return $sql;
    }
    protected function getCommandByName(Blueprint $blueprint, $name)
    {
        $commands = $this->getCommandsByName($blueprint, $name);
        if (count($commands) > 0) {
            return reset($commands);
        }
    }
    protected function getCommandsByName(Blueprint $blueprint, $name)
    {
        return array_filter($blueprint->getCommands(), function ($value) use ($name) {
            return $value->name == $name;
        });
    }
    public function prefixArray($prefix, array $values)
    {
        return array_map(function ($value) use ($prefix) {
            return $prefix . ' ' . $value;
        }, $values);
    }
    public function wrapTable($table)
    {
        return parent::wrapTable($table instanceof Blueprint ? $table->getTable() : $table);
    }
    public function wrap($value, $prefixAlias = false)
    {
        return parent::wrap($value instanceof Fluent ? $value->name : $value, $prefixAlias);
    }
    protected function getDefaultValue($value)
    {
        if ($value instanceof Expression) {
            return $this->getValue($value);
        }
        if ($value instanceof BackedEnum) {
            return "'{$value->value}'";
        }
        return is_bool($value) ? "'" . (int) $value . "'" : "'" . (string) $value . "'";
    }
    public function getDoctrineTableDiff(Blueprint $blueprint, SchemaManager $schema)
    {
        $tableName = $this->getTablePrefix() . $blueprint->getTable();
        $table = $schema->introspectTable($tableName);
        return new TableDiff(tableName: $tableName, fromTable: $table);
    }
    public function getFluentCommands()
    {
        return $this->fluentCommands;
    }
    public function supportsSchemaTransactions()
    {
        return $this->transactions;
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Fluent;
class SqlServerGrammar extends Grammar
{
    protected $transactions = true;
    protected $modifiers = ['Collate', 'Nullable', 'Default', 'Persisted', 'Increment'];
    protected $serials = ['tinyInteger', 'smallInteger', 'mediumInteger', 'integer', 'bigInteger'];
    protected $fluentCommands = ['Default'];
    public function compileCreateDatabase($name, $connection)
    {
        return sprintf('create database %s', $this->wrapValue($name));
    }
    public function compileDropDatabaseIfExists($name)
    {
        return sprintf('drop database if exists %s', $this->wrapValue($name));
    }
    public function compileTableExists()
    {
        return "select * from sys.sysobjects where id = object_id(?) and xtype in ('U', 'V')";
    }
    public function compileTables()
    {
        return 'select t.name as name, SCHEMA_NAME(t.schema_id) as [schema], sum(u.total_pages) * 8 * 1024 as size ' . 'from sys.tables as t ' . 'join sys.partitions as p on p.object_id = t.object_id ' . 'join sys.allocation_units as u on u.container_id = p.hobt_id ' . 'group by t.name, t.schema_id ' . 'order by t.name';
    }
    public function compileViews()
    {
        return 'select name, SCHEMA_NAME(v.schema_id) as [schema], definition from sys.views as v ' . 'inner join sys.sql_modules as m on v.object_id = m.object_id ' . 'order by name';
    }
    public function compileGetAllTables()
    {
        return "select name, type from sys.tables where type = 'U'";
    }
    public function compileGetAllViews()
    {
        return "select name, type from sys.objects where type = 'V'";
    }
    public function compileColumnListing($table)
    {
        return "select name from sys.columns where object_id = object_id('{$table}')";
    }
    public function compileColumns($table)
    {
        return sprintf('select col.name, type.name as type_name, ' . 'col.max_length as length, col.precision as precision, col.scale as places, ' . 'col.is_nullable as nullable, def.definition as [default], ' . 'col.is_identity as autoincrement, col.collation_name as collation, ' . 'cast(prop.value as nvarchar(max)) as comment ' . 'from sys.columns as col ' . 'join sys.types as type on col.user_type_id = type.user_type_id ' . 'join sys.objects as obj on col.object_id = obj.object_id ' . 'join sys.schemas as scm on obj.schema_id = scm.schema_id ' . 'left join sys.default_constraints def on col.default_object_id = def.object_id and col.object_id = def.parent_object_id ' . "left join sys.extended_properties as prop on obj.object_id = prop.major_id and col.column_id = prop.minor_id and prop.name = 'MS_Description' " . "where obj.type in ('U', 'V') and obj.name = %s and scm.name = SCHEMA_NAME() " . 'order by col.column_id', $this->quoteString($table));
    }
    public function compileIndexes($table)
    {
        return sprintf("select idx.name as name, string_agg(col.name, ',') within group (order by idxcol.key_ordinal) as columns, " . 'idx.type_desc as [type], idx.is_unique as [unique], idx.is_primary_key as [primary] ' . 'from sys.indexes as idx ' . 'join sys.tables as tbl on idx.object_id = tbl.object_id ' . 'join sys.schemas as scm on tbl.schema_id = scm.schema_id ' . 'join sys.index_columns as idxcol on idx.object_id = idxcol.object_id and idx.index_id = idxcol.index_id ' . 'join sys.columns as col on idxcol.object_id = col.object_id and idxcol.column_id = col.column_id ' . 'where tbl.name = %s and scm.name = SCHEMA_NAME() ' . 'group by idx.name, idx.type_desc, idx.is_unique, idx.is_primary_key', $this->quoteString($table));
    }
    public function compileForeignKeys($table)
    {
        return sprintf('select fk.name as name, ' . "string_agg(lc.name, ',') within group (order by fkc.constraint_column_id) as columns, " . 'fs.name as foreign_schema, ft.name as foreign_table, ' . "string_agg(fc.name, ',') within group (order by fkc.constraint_column_id) as foreign_columns, " . 'fk.update_referential_action_desc as on_update, ' . 'fk.delete_referential_action_desc as on_delete ' . 'from sys.foreign_keys as fk ' . 'join sys.foreign_key_columns as fkc on fkc.constraint_object_id = fk.object_id ' . 'join sys.tables as lt on lt.object_id = fk.parent_object_id ' . 'join sys.schemas as ls on lt.schema_id = ls.schema_id ' . 'join sys.columns as lc on fkc.parent_object_id = lc.object_id and fkc.parent_column_id = lc.column_id ' . 'join sys.tables as ft on ft.object_id = fk.referenced_object_id ' . 'join sys.schemas as fs on ft.schema_id = fs.schema_id ' . 'join sys.columns as fc on fkc.referenced_object_id = fc.object_id and fkc.referenced_column_id = fc.column_id ' . 'where lt.name = %s and ls.name = SCHEMA_NAME() ' . 'group by fk.name, fs.name, ft.name, fk.update_referential_action_desc, fk.delete_referential_action_desc', $this->quoteString($table));
    }
    public function compileCreate(Blueprint $blueprint, Fluent $command)
    {
        $columns = implode(', ', $this->getColumns($blueprint));
        return 'create table ' . $this->wrapTable($blueprint) . " ({$columns})";
    }
    public function compileAdd(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('alter table %s add %s', $this->wrapTable($blueprint), implode(', ', $this->getColumns($blueprint)));
    }
    public function compileRenameColumn(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        return $connection->usingNativeSchemaOperations() ? sprintf("sp_rename '%s', %s, 'COLUMN'", $this->wrap($blueprint->getTable() . '.' . $command->from), $this->wrap($command->to)) : parent::compileRenameColumn($blueprint, $command, $connection);
    }
    public function compileChange(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        if (!$connection->usingNativeSchemaOperations()) {
            return parent::compileChange($blueprint, $command, $connection);
        }
        $changes = [$this->compileDropDefaultConstraint($blueprint, $command)];
        foreach ($blueprint->getChangedColumns() as $column) {
            $sql = sprintf('alter table %s alter column %s %s', $this->wrapTable($blueprint), $this->wrap($column), $this->getType($column));
            foreach ($this->modifiers as $modifier) {
                if (method_exists($this, $method = "modify{$modifier}")) {
                    $sql .= $this->{$method}($blueprint, $column);
                }
            }
            $changes[] = $sql;
        }
        return $changes;
    }
    public function compilePrimary(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('alter table %s add constraint %s primary key (%s)', $this->wrapTable($blueprint), $this->wrap($command->index), $this->columnize($command->columns));
    }
    public function compileUnique(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('create unique index %s on %s (%s)', $this->wrap($command->index), $this->wrapTable($blueprint), $this->columnize($command->columns));
    }
    public function compileIndex(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('create index %s on %s (%s)', $this->wrap($command->index), $this->wrapTable($blueprint), $this->columnize($command->columns));
    }
    public function compileSpatialIndex(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('create spatial index %s on %s (%s)', $this->wrap($command->index), $this->wrapTable($blueprint), $this->columnize($command->columns));
    }
    public function compileDefault(Blueprint $blueprint, Fluent $command)
    {
        if ($command->column->change && !is_null($command->column->default)) {
            return sprintf('alter table %s add default %s for %s', $this->wrapTable($blueprint), $this->getDefaultValue($command->column->default), $this->wrap($command->column));
        }
    }
    public function compileDrop(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table ' . $this->wrapTable($blueprint);
    }
    public function compileDropIfExists(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('if exists (select * from sys.sysobjects where id = object_id(%s, \'U\')) drop table %s', "'" . str_replace("'", "''", $this->getTablePrefix() . $blueprint->getTable()) . "'", $this->wrapTable($blueprint));
    }
    public function compileDropAllTables()
    {
        return "EXEC sp_msforeachtable 'DROP TABLE ?'";
    }
    public function compileDropColumn(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->wrapArray($command->columns);
        $dropExistingConstraintsSql = $this->compileDropDefaultConstraint($blueprint, $command) . ';';
        return $dropExistingConstraintsSql . 'alter table ' . $this->wrapTable($blueprint) . ' drop column ' . implode(', ', $columns);
    }
    public function compileDropDefaultConstraint(Blueprint $blueprint, Fluent $command)
    {
        $columns = $command->name === 'change' ? "'" . collect($blueprint->getChangedColumns())->pluck('name')->implode("','") . "'" : "'" . implode("','", $command->columns) . "'";
        $tableName = $this->getTablePrefix() . $blueprint->getTable();
        $sql = "DECLARE @sql NVARCHAR(MAX) = '';";
        $sql .= "SELECT @sql += 'ALTER TABLE [dbo].[{$tableName}] DROP CONSTRAINT ' + OBJECT_NAME([default_object_id]) + ';' ";
        $sql .= 'FROM sys.columns ';
        $sql .= "WHERE [object_id] = OBJECT_ID('[dbo].[{$tableName}]') AND [name] in ({$columns}) AND [default_object_id] <> 0;";
        $sql .= 'EXEC(@sql)';
        return $sql;
    }
    public function compileDropPrimary(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "alter table {$this->wrapTable($blueprint)} drop constraint {$index}";
    }
    public function compileDropUnique(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "drop index {$index} on {$this->wrapTable($blueprint)}";
    }
    public function compileDropIndex(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "drop index {$index} on {$this->wrapTable($blueprint)}";
    }
    public function compileDropSpatialIndex(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileDropIndex($blueprint, $command);
    }
    public function compileDropForeign(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "alter table {$this->wrapTable($blueprint)} drop constraint {$index}";
    }
    public function compileRename(Blueprint $blueprint, Fluent $command)
    {
        $from = $this->wrapTable($blueprint);
        return "sp_rename {$from}, " . $this->wrapTable($command->to);
    }
    public function compileRenameIndex(Blueprint $blueprint, Fluent $command)
    {
        return sprintf("sp_rename N'%s', %s, N'INDEX'", $this->wrap($blueprint->getTable() . '.' . $command->from), $this->wrap($command->to));
    }
    public function compileEnableForeignKeyConstraints()
    {
        return 'EXEC sp_msforeachtable @command1="print \'?\'", @command2="ALTER TABLE ? WITH CHECK CHECK CONSTRAINT all";';
    }
    public function compileDisableForeignKeyConstraints()
    {
        return 'EXEC sp_msforeachtable "ALTER TABLE ? NOCHECK CONSTRAINT all";';
    }
    public function compileDropAllForeignKeys()
    {
        return "DECLARE @sql NVARCHAR(MAX) = N'';\n            SELECT @sql += 'ALTER TABLE '\n                + QUOTENAME(OBJECT_SCHEMA_NAME(parent_object_id)) + '.' + + QUOTENAME(OBJECT_NAME(parent_object_id))\n                + ' DROP CONSTRAINT ' + QUOTENAME(name) + ';'\n            FROM sys.foreign_keys;\n\n            EXEC sp_executesql @sql;";
    }
    public function compileDropAllViews()
    {
        return "DECLARE @sql NVARCHAR(MAX) = N'';\n            SELECT @sql += 'DROP VIEW ' + QUOTENAME(OBJECT_SCHEMA_NAME(object_id)) + '.' + QUOTENAME(name) + ';'\n            FROM sys.views;\n\n            EXEC sp_executesql @sql;";
    }
    protected function typeChar(Fluent $column)
    {
        return "nchar({$column->length})";
    }
    protected function typeString(Fluent $column)
    {
        return "nvarchar({$column->length})";
    }
    protected function typeTinyText(Fluent $column)
    {
        return 'nvarchar(255)';
    }
    protected function typeText(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeMediumText(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeLongText(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeInteger(Fluent $column)
    {
        return 'int';
    }
    protected function typeBigInteger(Fluent $column)
    {
        return 'bigint';
    }
    protected function typeMediumInteger(Fluent $column)
    {
        return 'int';
    }
    protected function typeTinyInteger(Fluent $column)
    {
        return 'tinyint';
    }
    protected function typeSmallInteger(Fluent $column)
    {
        return 'smallint';
    }
    protected function typeFloat(Fluent $column)
    {
        return 'float';
    }
    protected function typeDouble(Fluent $column)
    {
        return 'float';
    }
    protected function typeDecimal(Fluent $column)
    {
        return "decimal({$column->total}, {$column->places})";
    }
    protected function typeBoolean(Fluent $column)
    {
        return 'bit';
    }
    protected function typeEnum(Fluent $column)
    {
        return sprintf('nvarchar(255) check ("%s" in (%s))', $column->name, $this->quoteString($column->allowed));
    }
    protected function typeJson(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeJsonb(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeDate(Fluent $column)
    {
        return 'date';
    }
    protected function typeDateTime(Fluent $column)
    {
        return $this->typeTimestamp($column);
    }
    protected function typeDateTimeTz(Fluent $column)
    {
        return $this->typeTimestampTz($column);
    }
    protected function typeTime(Fluent $column)
    {
        return $column->precision ? "time({$column->precision})" : 'time';
    }
    protected function typeTimeTz(Fluent $column)
    {
        return $this->typeTime($column);
    }
    protected function typeTimestamp(Fluent $column)
    {
        if ($column->useCurrent) {
            $column->default(new Expression('CURRENT_TIMESTAMP'));
        }
        return $column->precision ? "datetime2({$column->precision})" : 'datetime';
    }
    protected function typeTimestampTz(Fluent $column)
    {
        if ($column->useCurrent) {
            $column->default(new Expression('CURRENT_TIMESTAMP'));
        }
        return $column->precision ? "datetimeoffset({$column->precision})" : 'datetimeoffset';
    }
    protected function typeYear(Fluent $column)
    {
        return $this->typeInteger($column);
    }
    protected function typeBinary(Fluent $column)
    {
        return 'varbinary(max)';
    }
    protected function typeUuid(Fluent $column)
    {
        return 'uniqueidentifier';
    }
    protected function typeIpAddress(Fluent $column)
    {
        return 'nvarchar(45)';
    }
    protected function typeMacAddress(Fluent $column)
    {
        return 'nvarchar(17)';
    }
    public function typeGeometry(Fluent $column)
    {
        return 'geography';
    }
    public function typePoint(Fluent $column)
    {
        return 'geography';
    }
    public function typeLineString(Fluent $column)
    {
        return 'geography';
    }
    public function typePolygon(Fluent $column)
    {
        return 'geography';
    }
    public function typeGeometryCollection(Fluent $column)
    {
        return 'geography';
    }
    public function typeMultiPoint(Fluent $column)
    {
        return 'geography';
    }
    public function typeMultiLineString(Fluent $column)
    {
        return 'geography';
    }
    public function typeMultiPolygon(Fluent $column)
    {
        return 'geography';
    }
    protected function typeComputed(Fluent $column)
    {
        return "as ({$this->getValue($column->expression)})";
    }
    protected function modifyCollate(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->collation)) {
            return ' collate ' . $column->collation;
        }
    }
    protected function modifyNullable(Blueprint $blueprint, Fluent $column)
    {
        if ($column->type !== 'computed') {
            return $column->nullable ? ' null' : ' not null';
        }
    }
    protected function modifyDefault(Blueprint $blueprint, Fluent $column)
    {
        if (!$column->change && !is_null($column->default)) {
            return ' default ' . $this->getDefaultValue($column->default);
        }
    }
    protected function modifyIncrement(Blueprint $blueprint, Fluent $column)
    {
        if (!$column->change && in_array($column->type, $this->serials) && $column->autoIncrement) {
            return ' identity primary key';
        }
    }
    protected function modifyPersisted(Blueprint $blueprint, Fluent $column)
    {
        if ($column->change) {
            if ($column->type === 'computed') {
                return $column->persisted ? ' add persisted' : ' drop persisted';
            }
            return null;
        }
        if ($column->persisted) {
            return ' persisted';
        }
    }
    public function wrapTable($table)
    {
        if ($table instanceof Blueprint && $table->temporary) {
            $this->setTablePrefix('#');
        }
        return parent::wrapTable($table);
    }
    public function quoteString($value)
    {
        if (is_array($value)) {
            return implode(', ', array_map([$this, __FUNCTION__], $value));
        }
        return "N'{$value}'";
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Fluent;
use RuntimeException;
class MySqlGrammar extends Grammar
{
    protected $modifiers = ['Unsigned', 'Charset', 'Collate', 'VirtualAs', 'StoredAs', 'Nullable', 'Srid', 'Default', 'OnUpdate', 'Invisible', 'Increment', 'Comment', 'After', 'First'];
    protected $serials = ['bigInteger', 'integer', 'mediumInteger', 'smallInteger', 'tinyInteger'];
    protected $fluentCommands = ['AutoIncrementStartingValues'];
    public function compileCreateDatabase($name, $connection)
    {
        $charset = $connection->getConfig('charset');
        $collation = $connection->getConfig('collation');
        if (!$charset || !$collation) {
            return sprintf('create database %s', $this->wrapValue($name));
        }
        return sprintf('create database %s default character set %s default collate %s', $this->wrapValue($name), $this->wrapValue($charset), $this->wrapValue($collation));
    }
    public function compileDropDatabaseIfExists($name)
    {
        return sprintf('drop database if exists %s', $this->wrapValue($name));
    }
    public function compileTableExists()
    {
        return "select * from information_schema.tables where table_schema = ? and table_name = ? and table_type = 'BASE TABLE'";
    }
    public function compileTables($database)
    {
        return sprintf('select table_name as `name`, (data_length + index_length) as `size`, ' . 'table_comment as `comment`, engine as `engine`, table_collation as `collation` ' . "from information_schema.tables where table_schema = %s and table_type in ('BASE TABLE', 'SYSTEM VERSIONED') " . 'order by table_name', $this->quoteString($database));
    }
    public function compileViews($database)
    {
        return sprintf('select table_name as `name`, view_definition as `definition` ' . 'from information_schema.views where table_schema = %s ' . 'order by table_name', $this->quoteString($database));
    }
    public function compileGetAllTables()
    {
        return 'SHOW FULL TABLES WHERE table_type = \'BASE TABLE\'';
    }
    public function compileGetAllViews()
    {
        return 'SHOW FULL TABLES WHERE table_type = \'VIEW\'';
    }
    public function compileColumnListing()
    {
        return 'select column_name as `column_name` from information_schema.columns where table_schema = ? and table_name = ?';
    }
    public function compileColumns($database, $table)
    {
        return sprintf('select column_name as `name`, data_type as `type_name`, column_type as `type`, ' . 'collation_name as `collation`, is_nullable as `nullable`, ' . 'column_default as `default`, column_comment as `comment`, extra as `extra` ' . 'from information_schema.columns where table_schema = %s and table_name = %s ' . 'order by ordinal_position asc', $this->quoteString($database), $this->quoteString($table));
    }
    public function compileIndexes($database, $table)
    {
        return sprintf('select index_name as `name`, group_concat(column_name order by seq_in_index) as `columns`, ' . 'index_type as `type`, not non_unique as `unique` ' . 'from information_schema.statistics where table_schema = %s and table_name = %s ' . 'group by index_name, index_type, non_unique', $this->quoteString($database), $this->quoteString($table));
    }
    public function compileForeignKeys($database, $table)
    {
        return sprintf('select kc.constraint_name as `name`, ' . 'group_concat(kc.column_name order by kc.ordinal_position) as `columns`, ' . 'kc.referenced_table_schema as `foreign_schema`, ' . 'kc.referenced_table_name as `foreign_table`, ' . 'group_concat(kc.referenced_column_name order by kc.ordinal_position) as `foreign_columns`, ' . 'rc.update_rule as `on_update`, ' . 'rc.delete_rule as `on_delete` ' . 'from information_schema.key_column_usage kc join information_schema.referential_constraints rc ' . 'on kc.constraint_schema = rc.constraint_schema and kc.constraint_name = rc.constraint_name ' . 'where kc.table_schema = %s and kc.table_name = %s and kc.referenced_table_name is not null ' . 'group by kc.constraint_name, kc.referenced_table_schema, kc.referenced_table_name, rc.update_rule, rc.delete_rule', $this->quoteString($database), $this->quoteString($table));
    }
    public function compileCreate(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        $sql = $this->compileCreateTable($blueprint, $command, $connection);
        $sql = $this->compileCreateEncoding($sql, $connection, $blueprint);
        return $this->compileCreateEngine($sql, $connection, $blueprint);
    }
    protected function compileCreateTable($blueprint, $command, $connection)
    {
        $tableStructure = $this->getColumns($blueprint);
        if ($primaryKey = $this->getCommandByName($blueprint, 'primary')) {
            $tableStructure[] = sprintf('primary key %s(%s)', $primaryKey->algorithm ? 'using ' . $primaryKey->algorithm : '', $this->columnize($primaryKey->columns));
            $primaryKey->shouldBeSkipped = true;
        }
        return sprintf('%s table %s (%s)', $blueprint->temporary ? 'create temporary' : 'create', $this->wrapTable($blueprint), implode(', ', $tableStructure));
    }
    protected function compileCreateEncoding($sql, Connection $connection, Blueprint $blueprint)
    {
        if (isset($blueprint->charset)) {
            $sql .= ' default character set ' . $blueprint->charset;
        } elseif (!is_null($charset = $connection->getConfig('charset'))) {
            $sql .= ' default character set ' . $charset;
        }
        if (isset($blueprint->collation)) {
            $sql .= " collate '{$blueprint->collation}'";
        } elseif (!is_null($collation = $connection->getConfig('collation'))) {
            $sql .= " collate '{$collation}'";
        }
        return $sql;
    }
    protected function compileCreateEngine($sql, Connection $connection, Blueprint $blueprint)
    {
        if (isset($blueprint->engine)) {
            return $sql . ' engine = ' . $blueprint->engine;
        } elseif (!is_null($engine = $connection->getConfig('engine'))) {
            return $sql . ' engine = ' . $engine;
        }
        return $sql;
    }
    public function compileAdd(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->prefixArray('add', $this->getColumns($blueprint));
        return 'alter table ' . $this->wrapTable($blueprint) . ' ' . implode(', ', $columns);
    }
    public function compileAutoIncrementStartingValues(Blueprint $blueprint, Fluent $command)
    {
        if ($command->column->autoIncrement && $value = $command->column->get('startingValue', $command->column->get('from'))) {
            return 'alter table ' . $this->wrapTable($blueprint) . ' auto_increment = ' . $value;
        }
    }
    public function compileRenameColumn(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        return $connection->usingNativeSchemaOperations() ? sprintf('alter table %s rename column %s to %s', $this->wrapTable($blueprint), $this->wrap($command->from), $this->wrap($command->to)) : parent::compileRenameColumn($blueprint, $command, $connection);
    }
    public function compileChange(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        if (!$connection->usingNativeSchemaOperations()) {
            return parent::compileChange($blueprint, $command, $connection);
        }
        $columns = [];
        foreach ($blueprint->getChangedColumns() as $column) {
            $sql = sprintf('%s %s%s %s', is_null($column->renameTo) ? 'modify' : 'change', $this->wrap($column), is_null($column->renameTo) ? '' : ' ' . $this->wrap($column->renameTo), $this->getType($column));
            $columns[] = $this->addModifiers($sql, $blueprint, $column);
        }
        return 'alter table ' . $this->wrapTable($blueprint) . ' ' . implode(', ', $columns);
    }
    public function compilePrimary(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('alter table %s add primary key %s(%s)', $this->wrapTable($blueprint), $command->algorithm ? 'using ' . $command->algorithm : '', $this->columnize($command->columns));
    }
    public function compileUnique(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileKey($blueprint, $command, 'unique');
    }
    public function compileIndex(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileKey($blueprint, $command, 'index');
    }
    public function compileFullText(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileKey($blueprint, $command, 'fulltext');
    }
    public function compileSpatialIndex(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileKey($blueprint, $command, 'spatial index');
    }
    protected function compileKey(Blueprint $blueprint, Fluent $command, $type)
    {
        return sprintf('alter table %s add %s %s%s(%s)', $this->wrapTable($blueprint), $type, $this->wrap($command->index), $command->algorithm ? ' using ' . $command->algorithm : '', $this->columnize($command->columns));
    }
    public function compileDrop(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table ' . $this->wrapTable($blueprint);
    }
    public function compileDropIfExists(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table if exists ' . $this->wrapTable($blueprint);
    }
    public function compileDropColumn(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->prefixArray('drop', $this->wrapArray($command->columns));
        return 'alter table ' . $this->wrapTable($blueprint) . ' ' . implode(', ', $columns);
    }
    public function compileDropPrimary(Blueprint $blueprint, Fluent $command)
    {
        return 'alter table ' . $this->wrapTable($blueprint) . ' drop primary key';
    }
    public function compileDropUnique(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "alter table {$this->wrapTable($blueprint)} drop index {$index}";
    }
    public function compileDropIndex(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "alter table {$this->wrapTable($blueprint)} drop index {$index}";
    }
    public function compileDropFullText(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileDropIndex($blueprint, $command);
    }
    public function compileDropSpatialIndex(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileDropIndex($blueprint, $command);
    }
    public function compileDropForeign(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "alter table {$this->wrapTable($blueprint)} drop foreign key {$index}";
    }
    public function compileRename(Blueprint $blueprint, Fluent $command)
    {
        $from = $this->wrapTable($blueprint);
        return "rename table {$from} to " . $this->wrapTable($command->to);
    }
    public function compileRenameIndex(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('alter table %s rename index %s to %s', $this->wrapTable($blueprint), $this->wrap($command->from), $this->wrap($command->to));
    }
    public function compileDropAllTables($tables)
    {
        return 'drop table ' . implode(',', $this->wrapArray($tables));
    }
    public function compileDropAllViews($views)
    {
        return 'drop view ' . implode(',', $this->wrapArray($views));
    }
    public function compileEnableForeignKeyConstraints()
    {
        return 'SET FOREIGN_KEY_CHECKS=1;';
    }
    public function compileDisableForeignKeyConstraints()
    {
        return 'SET FOREIGN_KEY_CHECKS=0;';
    }
    public function compileTableComment(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('alter table %s comment = %s', $this->wrapTable($blueprint), "'" . str_replace("'", "''", $command->comment) . "'");
    }
    protected function typeChar(Fluent $column)
    {
        return "char({$column->length})";
    }
    protected function typeString(Fluent $column)
    {
        return "varchar({$column->length})";
    }
    protected function typeTinyText(Fluent $column)
    {
        return 'tinytext';
    }
    protected function typeText(Fluent $column)
    {
        return 'text';
    }
    protected function typeMediumText(Fluent $column)
    {
        return 'mediumtext';
    }
    protected function typeLongText(Fluent $column)
    {
        return 'longtext';
    }
    protected function typeBigInteger(Fluent $column)
    {
        return 'bigint';
    }
    protected function typeInteger(Fluent $column)
    {
        return 'int';
    }
    protected function typeMediumInteger(Fluent $column)
    {
        return 'mediumint';
    }
    protected function typeTinyInteger(Fluent $column)
    {
        return 'tinyint';
    }
    protected function typeSmallInteger(Fluent $column)
    {
        return 'smallint';
    }
    protected function typeFloat(Fluent $column)
    {
        return $this->typeDouble($column);
    }
    protected function typeDouble(Fluent $column)
    {
        if ($column->total && $column->places) {
            return "double({$column->total}, {$column->places})";
        }
        return 'double';
    }
    protected function typeDecimal(Fluent $column)
    {
        return "decimal({$column->total}, {$column->places})";
    }
    protected function typeBoolean(Fluent $column)
    {
        return 'tinyint(1)';
    }
    protected function typeEnum(Fluent $column)
    {
        return sprintf('enum(%s)', $this->quoteString($column->allowed));
    }
    protected function typeSet(Fluent $column)
    {
        return sprintf('set(%s)', $this->quoteString($column->allowed));
    }
    protected function typeJson(Fluent $column)
    {
        return 'json';
    }
    protected function typeJsonb(Fluent $column)
    {
        return 'json';
    }
    protected function typeDate(Fluent $column)
    {
        return 'date';
    }
    protected function typeDateTime(Fluent $column)
    {
        $current = $column->precision ? "CURRENT_TIMESTAMP({$column->precision})" : 'CURRENT_TIMESTAMP';
        if ($column->useCurrent) {
            $column->default(new Expression($current));
        }
        if ($column->useCurrentOnUpdate) {
            $column->onUpdate(new Expression($current));
        }
        return $column->precision ? "datetime({$column->precision})" : 'datetime';
    }
    protected function typeDateTimeTz(Fluent $column)
    {
        return $this->typeDateTime($column);
    }
    protected function typeTime(Fluent $column)
    {
        return $column->precision ? "time({$column->precision})" : 'time';
    }
    protected function typeTimeTz(Fluent $column)
    {
        return $this->typeTime($column);
    }
    protected function typeTimestamp(Fluent $column)
    {
        $current = $column->precision ? "CURRENT_TIMESTAMP({$column->precision})" : 'CURRENT_TIMESTAMP';
        if ($column->useCurrent) {
            $column->default(new Expression($current));
        }
        if ($column->useCurrentOnUpdate) {
            $column->onUpdate(new Expression($current));
        }
        return $column->precision ? "timestamp({$column->precision})" : 'timestamp';
    }
    protected function typeTimestampTz(Fluent $column)
    {
        return $this->typeTimestamp($column);
    }
    protected function typeYear(Fluent $column)
    {
        return 'year';
    }
    protected function typeBinary(Fluent $column)
    {
        return 'blob';
    }
    protected function typeUuid(Fluent $column)
    {
        return 'char(36)';
    }
    protected function typeIpAddress(Fluent $column)
    {
        return 'varchar(45)';
    }
    protected function typeMacAddress(Fluent $column)
    {
        return 'varchar(17)';
    }
    public function typeGeometry(Fluent $column)
    {
        return 'geometry';
    }
    public function typePoint(Fluent $column)
    {
        return 'point';
    }
    public function typeLineString(Fluent $column)
    {
        return 'linestring';
    }
    public function typePolygon(Fluent $column)
    {
        return 'polygon';
    }
    public function typeGeometryCollection(Fluent $column)
    {
        return 'geometrycollection';
    }
    public function typeMultiPoint(Fluent $column)
    {
        return 'multipoint';
    }
    public function typeMultiLineString(Fluent $column)
    {
        return 'multilinestring';
    }
    public function typeMultiPolygon(Fluent $column)
    {
        return 'multipolygon';
    }
    protected function typeComputed(Fluent $column)
    {
        throw new RuntimeException('This database driver requires a type, see the virtualAs / storedAs modifiers.');
    }
    protected function modifyVirtualAs(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($virtualAs = $column->virtualAsJson)) {
            if ($this->isJsonSelector($virtualAs)) {
                $virtualAs = $this->wrapJsonSelector($virtualAs);
            }
            return " as ({$virtualAs})";
        }
        if (!is_null($virtualAs = $column->virtualAs)) {
            return " as ({$this->getValue($virtualAs)})";
        }
    }
    protected function modifyStoredAs(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($storedAs = $column->storedAsJson)) {
            if ($this->isJsonSelector($storedAs)) {
                $storedAs = $this->wrapJsonSelector($storedAs);
            }
            return " as ({$storedAs}) stored";
        }
        if (!is_null($storedAs = $column->storedAs)) {
            return " as ({$this->getValue($storedAs)}) stored";
        }
    }
    protected function modifyUnsigned(Blueprint $blueprint, Fluent $column)
    {
        if ($column->unsigned) {
            return ' unsigned';
        }
    }
    protected function modifyCharset(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->charset)) {
            return ' character set ' . $column->charset;
        }
    }
    protected function modifyCollate(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->collation)) {
            return " collate '{$column->collation}'";
        }
    }
    protected function modifyNullable(Blueprint $blueprint, Fluent $column)
    {
        if (is_null($column->virtualAs) && is_null($column->virtualAsJson) && is_null($column->storedAs) && is_null($column->storedAsJson)) {
            return $column->nullable ? ' null' : ' not null';
        }
        if ($column->nullable === false) {
            return ' not null';
        }
    }
    protected function modifyInvisible(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->invisible)) {
            return ' invisible';
        }
    }
    protected function modifyDefault(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->default)) {
            return ' default ' . $this->getDefaultValue($column->default);
        }
    }
    protected function modifyOnUpdate(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->onUpdate)) {
            return ' on update ' . $this->getValue($column->onUpdate);
        }
    }
    protected function modifyIncrement(Blueprint $blueprint, Fluent $column)
    {
        if (in_array($column->type, $this->serials) && $column->autoIncrement) {
            return ' auto_increment primary key';
        }
    }
    protected function modifyFirst(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->first)) {
            return ' first';
        }
    }
    protected function modifyAfter(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->after)) {
            return ' after ' . $this->wrap($column->after);
        }
    }
    protected function modifyComment(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->comment)) {
            return " comment '" . addslashes($column->comment) . "'";
        }
    }
    protected function modifySrid(Blueprint $blueprint, Fluent $column)
    {
        if (is_int($column->srid) && $column->srid > 0) {
            return ' srid ' . $column->srid;
        }
    }
    protected function wrapValue($value)
    {
        if ($value !== '*') {
            return '`' . str_replace('`', '``', $value) . '`';
        }
        return $value;
    }
    protected function wrapJsonSelector($value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($value);
        return 'json_unquote(json_extract(' . $field . $path . '))';
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Fluent;
use LogicException;
class PostgresGrammar extends Grammar
{
    protected $transactions = true;
    protected $modifiers = ['Collate', 'Nullable', 'Default', 'VirtualAs', 'StoredAs', 'GeneratedAs', 'Increment'];
    protected $serials = ['bigInteger', 'integer', 'mediumInteger', 'smallInteger', 'tinyInteger'];
    protected $fluentCommands = ['AutoIncrementStartingValues', 'Comment'];
    public function compileCreateDatabase($name, $connection)
    {
        return sprintf('create database %s encoding %s', $this->wrapValue($name), $this->wrapValue($connection->getConfig('charset')));
    }
    public function compileDropDatabaseIfExists($name)
    {
        return sprintf('drop database if exists %s', $this->wrapValue($name));
    }
    public function compileTableExists()
    {
        return "select * from information_schema.tables where table_catalog = ? and table_schema = ? and table_name = ? and table_type = 'BASE TABLE'";
    }
    public function compileTables()
    {
        return 'select c.relname as name, n.nspname as schema, pg_total_relation_size(c.oid) as size, ' . "obj_description(c.oid, 'pg_class') as comment from pg_class c, pg_namespace n " . "where c.relkind in ('r', 'p') and n.oid = c.relnamespace and n.nspname not in ('pg_catalog', 'information_schema') " . 'order by c.relname';
    }
    public function compileViews()
    {
        return "select viewname as name, schemaname as schema, definition from pg_views where schemaname not in ('pg_catalog', 'information_schema') order by viewname";
    }
    public function compileTypes()
    {
        return 'select t.typname as name, n.nspname as schema, t.typtype as type, t.typcategory as category, ' . "((t.typinput = 'array_in'::regproc and t.typoutput = 'array_out'::regproc) or t.typtype = 'm') as implicit " . 'from pg_type t join pg_namespace n on n.oid = t.typnamespace ' . 'left join pg_class c on c.oid = t.typrelid ' . 'left join pg_type el on el.oid = t.typelem ' . 'left join pg_class ce on ce.oid = el.typrelid ' . "where ((t.typrelid = 0 and (ce.relkind = 'c' or ce.relkind is null)) or c.relkind = 'c') " . "and not exists (select 1 from pg_depend d where d.objid in (t.oid, t.typelem) and d.deptype = 'e') " . "and n.nspname not in ('pg_catalog', 'information_schema')";
    }
    public function compileGetAllTables($searchPath)
    {
        return "select tablename, concat('\"', schemaname, '\".\"', tablename, '\"') as qualifiedname from pg_catalog.pg_tables where schemaname in ('" . implode("','", (array) $searchPath) . "')";
    }
    public function compileGetAllViews($searchPath)
    {
        return "select viewname, concat('\"', schemaname, '\".\"', viewname, '\"') as qualifiedname from pg_catalog.pg_views where schemaname in ('" . implode("','", (array) $searchPath) . "')";
    }
    public function compileColumnListing()
    {
        return 'select column_name from information_schema.columns where table_catalog = ? and table_schema = ? and table_name = ?';
    }
    public function compileColumns($database, $schema, $table)
    {
        return sprintf('select a.attname as name, t.typname as type_name, format_type(a.atttypid, a.atttypmod) as type, ' . '(select tc.collcollate from pg_catalog.pg_collation tc where tc.oid = a.attcollation) as collation, ' . 'not a.attnotnull as nullable, ' . '(select pg_get_expr(adbin, adrelid) from pg_attrdef where c.oid = pg_attrdef.adrelid and pg_attrdef.adnum = a.attnum) as default, ' . 'col_description(c.oid, a.attnum) as comment ' . 'from pg_attribute a, pg_class c, pg_type t, pg_namespace n ' . 'where c.relname = %s and n.nspname = %s and a.attnum > 0 and a.attrelid = c.oid and a.atttypid = t.oid and n.oid = c.relnamespace ' . 'order by a.attnum', $this->quoteString($table), $this->quoteString($schema));
    }
    public function compileIndexes($schema, $table)
    {
        return sprintf("select ic.relname as name, string_agg(a.attname, ',' order by indseq.ord) as columns, " . 'am.amname as "type", i.indisunique as "unique", i.indisprimary as "primary" ' . 'from pg_index i ' . 'join pg_class tc on tc.oid = i.indrelid ' . 'join pg_namespace tn on tn.oid = tc.relnamespace ' . 'join pg_class ic on ic.oid = i.indexrelid ' . 'join pg_am am on am.oid = ic.relam ' . 'join lateral unnest(i.indkey) with ordinality as indseq(num, ord) on true ' . 'left join pg_attribute a on a.attrelid = i.indrelid and a.attnum = indseq.num ' . 'where tc.relname = %s and tn.nspname = %s ' . 'group by ic.relname, am.amname, i.indisunique, i.indisprimary', $this->quoteString($table), $this->quoteString($schema));
    }
    public function compileForeignKeys($schema, $table)
    {
        return sprintf('select c.conname as name, ' . "string_agg(la.attname, ',' order by conseq.ord) as columns, " . 'fn.nspname as foreign_schema, fc.relname as foreign_table, ' . "string_agg(fa.attname, ',' order by conseq.ord) as foreign_columns, " . 'c.confupdtype as on_update, c.confdeltype as on_delete ' . 'from pg_constraint c ' . 'join pg_class tc on c.conrelid = tc.oid ' . 'join pg_namespace tn on tn.oid = tc.relnamespace ' . 'join pg_class fc on c.confrelid = fc.oid ' . 'join pg_namespace fn on fn.oid = fc.relnamespace ' . 'join lateral unnest(c.conkey) with ordinality as conseq(num, ord) on true ' . 'join pg_attribute la on la.attrelid = c.conrelid and la.attnum = conseq.num ' . 'join pg_attribute fa on fa.attrelid = c.confrelid and fa.attnum = c.confkey[conseq.ord] ' . "where c.contype = 'f' and tc.relname = %s and tn.nspname = %s " . 'group by c.conname, fn.nspname, fc.relname, c.confupdtype, c.confdeltype', $this->quoteString($table), $this->quoteString($schema));
    }
    public function compileCreate(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('%s table %s (%s)', $blueprint->temporary ? 'create temporary' : 'create', $this->wrapTable($blueprint), implode(', ', $this->getColumns($blueprint)));
    }
    public function compileAdd(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('alter table %s %s', $this->wrapTable($blueprint), implode(', ', $this->prefixArray('add column', $this->getColumns($blueprint))));
    }
    public function compileAutoIncrementStartingValues(Blueprint $blueprint, Fluent $command)
    {
        if ($command->column->autoIncrement && $value = $command->column->get('startingValue', $command->column->get('from'))) {
            return 'alter sequence ' . $blueprint->getTable() . '_' . $command->column->name . '_seq restart with ' . $value;
        }
    }
    public function compileRenameColumn(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        return $connection->usingNativeSchemaOperations() ? sprintf('alter table %s rename column %s to %s', $this->wrapTable($blueprint), $this->wrap($command->from), $this->wrap($command->to)) : parent::compileRenameColumn($blueprint, $command, $connection);
    }
    public function compileChange(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        if (!$connection->usingNativeSchemaOperations()) {
            return parent::compileChange($blueprint, $command, $connection);
        }
        $columns = [];
        foreach ($blueprint->getChangedColumns() as $column) {
            $changes = ['type ' . $this->getType($column) . $this->modifyCollate($blueprint, $column)];
            foreach ($this->modifiers as $modifier) {
                if ($modifier === 'Collate') {
                    continue;
                }
                if (method_exists($this, $method = "modify{$modifier}")) {
                    $constraints = (array) $this->{$method}($blueprint, $column);
                    foreach ($constraints as $constraint) {
                        $changes[] = $constraint;
                    }
                }
            }
            $columns[] = implode(', ', $this->prefixArray('alter column ' . $this->wrap($column), $changes));
        }
        return 'alter table ' . $this->wrapTable($blueprint) . ' ' . implode(', ', $columns);
    }
    public function compilePrimary(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->columnize($command->columns);
        return 'alter table ' . $this->wrapTable($blueprint) . " add primary key ({$columns})";
    }
    public function compileUnique(Blueprint $blueprint, Fluent $command)
    {
        $sql = sprintf('alter table %s add constraint %s unique (%s)', $this->wrapTable($blueprint), $this->wrap($command->index), $this->columnize($command->columns));
        if (!is_null($command->deferrable)) {
            $sql .= $command->deferrable ? ' deferrable' : ' not deferrable';
        }
        if ($command->deferrable && !is_null($command->initiallyImmediate)) {
            $sql .= $command->initiallyImmediate ? ' initially immediate' : ' initially deferred';
        }
        return $sql;
    }
    public function compileIndex(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('create index %s on %s%s (%s)', $this->wrap($command->index), $this->wrapTable($blueprint), $command->algorithm ? ' using ' . $command->algorithm : '', $this->columnize($command->columns));
    }
    public function compileFulltext(Blueprint $blueprint, Fluent $command)
    {
        $language = $command->language ?: 'english';
        $columns = array_map(function ($column) use ($language) {
            return "to_tsvector({$this->quoteString($language)}, {$this->wrap($column)})";
        }, $command->columns);
        return sprintf('create index %s on %s using gin ((%s))', $this->wrap($command->index), $this->wrapTable($blueprint), implode(' || ', $columns));
    }
    public function compileSpatialIndex(Blueprint $blueprint, Fluent $command)
    {
        $command->algorithm = 'gist';
        return $this->compileIndex($blueprint, $command);
    }
    public function compileForeign(Blueprint $blueprint, Fluent $command)
    {
        $sql = parent::compileForeign($blueprint, $command);
        if (!is_null($command->deferrable)) {
            $sql .= $command->deferrable ? ' deferrable' : ' not deferrable';
        }
        if ($command->deferrable && !is_null($command->initiallyImmediate)) {
            $sql .= $command->initiallyImmediate ? ' initially immediate' : ' initially deferred';
        }
        if (!is_null($command->notValid)) {
            $sql .= ' not valid';
        }
        return $sql;
    }
    public function compileDrop(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table ' . $this->wrapTable($blueprint);
    }
    public function compileDropIfExists(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table if exists ' . $this->wrapTable($blueprint);
    }
    public function compileDropAllTables($tables)
    {
        return 'drop table ' . implode(',', $this->escapeNames($tables)) . ' cascade';
    }
    public function compileDropAllViews($views)
    {
        return 'drop view ' . implode(',', $this->escapeNames($views)) . ' cascade';
    }
    public function compileDropAllTypes($types)
    {
        return 'drop type ' . implode(',', $this->escapeNames($types)) . ' cascade';
    }
    public function compileDropAllDomains($domains)
    {
        return 'drop domain ' . implode(',', $this->escapeNames($domains)) . ' cascade';
    }
    public function compileGetAllTypes()
    {
        return 'select distinct pg_type.typname from pg_type inner join pg_enum on pg_enum.enumtypid = pg_type.oid';
    }
    public function compileDropColumn(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->prefixArray('drop column', $this->wrapArray($command->columns));
        return 'alter table ' . $this->wrapTable($blueprint) . ' ' . implode(', ', $columns);
    }
    public function compileDropPrimary(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap("{$blueprint->getPrefix()}{$blueprint->getTable()}_pkey");
        return 'alter table ' . $this->wrapTable($blueprint) . " drop constraint {$index}";
    }
    public function compileDropUnique(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "alter table {$this->wrapTable($blueprint)} drop constraint {$index}";
    }
    public function compileDropIndex(Blueprint $blueprint, Fluent $command)
    {
        return "drop index {$this->wrap($command->index)}";
    }
    public function compileDropFullText(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileDropIndex($blueprint, $command);
    }
    public function compileDropSpatialIndex(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileDropIndex($blueprint, $command);
    }
    public function compileDropForeign(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "alter table {$this->wrapTable($blueprint)} drop constraint {$index}";
    }
    public function compileRename(Blueprint $blueprint, Fluent $command)
    {
        $from = $this->wrapTable($blueprint);
        return "alter table {$from} rename to " . $this->wrapTable($command->to);
    }
    public function compileRenameIndex(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('alter index %s rename to %s', $this->wrap($command->from), $this->wrap($command->to));
    }
    public function compileEnableForeignKeyConstraints()
    {
        return 'SET CONSTRAINTS ALL IMMEDIATE;';
    }
    public function compileDisableForeignKeyConstraints()
    {
        return 'SET CONSTRAINTS ALL DEFERRED;';
    }
    public function compileComment(Blueprint $blueprint, Fluent $command)
    {
        if (!is_null($comment = $command->column->comment) || $command->column->change) {
            return sprintf('comment on column %s.%s is %s', $this->wrapTable($blueprint), $this->wrap($command->column->name), is_null($comment) ? 'NULL' : "'" . str_replace("'", "''", $comment) . "'");
        }
    }
    public function compileTableComment(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('comment on table %s is %s', $this->wrapTable($blueprint), "'" . str_replace("'", "''", $command->comment) . "'");
    }
    public function escapeNames($names)
    {
        return array_map(static function ($name) {
            return '"' . collect(explode('.', $name))->map(fn($segment) => trim($segment, '\'"'))->implode('"."') . '"';
        }, $names);
    }
    protected function typeChar(Fluent $column)
    {
        if ($column->length) {
            return "char({$column->length})";
        }
        return 'char';
    }
    protected function typeString(Fluent $column)
    {
        if ($column->length) {
            return "varchar({$column->length})";
        }
        return 'varchar';
    }
    protected function typeTinyText(Fluent $column)
    {
        return 'varchar(255)';
    }
    protected function typeText(Fluent $column)
    {
        return 'text';
    }
    protected function typeMediumText(Fluent $column)
    {
        return 'text';
    }
    protected function typeLongText(Fluent $column)
    {
        return 'text';
    }
    protected function typeInteger(Fluent $column)
    {
        return $column->autoIncrement && is_null($column->generatedAs) ? 'serial' : 'integer';
    }
    protected function typeBigInteger(Fluent $column)
    {
        return $column->autoIncrement && is_null($column->generatedAs) ? 'bigserial' : 'bigint';
    }
    protected function typeMediumInteger(Fluent $column)
    {
        return $this->typeInteger($column);
    }
    protected function typeTinyInteger(Fluent $column)
    {
        return $this->typeSmallInteger($column);
    }
    protected function typeSmallInteger(Fluent $column)
    {
        return $column->autoIncrement && is_null($column->generatedAs) ? 'smallserial' : 'smallint';
    }
    protected function typeFloat(Fluent $column)
    {
        return $this->typeDouble($column);
    }
    protected function typeDouble(Fluent $column)
    {
        return 'double precision';
    }
    protected function typeReal(Fluent $column)
    {
        return 'real';
    }
    protected function typeDecimal(Fluent $column)
    {
        return "decimal({$column->total}, {$column->places})";
    }
    protected function typeBoolean(Fluent $column)
    {
        return 'boolean';
    }
    protected function typeEnum(Fluent $column)
    {
        return sprintf('varchar(255) check ("%s" in (%s))', $column->name, $this->quoteString($column->allowed));
    }
    protected function typeJson(Fluent $column)
    {
        return 'json';
    }
    protected function typeJsonb(Fluent $column)
    {
        return 'jsonb';
    }
    protected function typeDate(Fluent $column)
    {
        return 'date';
    }
    protected function typeDateTime(Fluent $column)
    {
        return $this->typeTimestamp($column);
    }
    protected function typeDateTimeTz(Fluent $column)
    {
        return $this->typeTimestampTz($column);
    }
    protected function typeTime(Fluent $column)
    {
        return 'time' . (is_null($column->precision) ? '' : "({$column->precision})") . ' without time zone';
    }
    protected function typeTimeTz(Fluent $column)
    {
        return 'time' . (is_null($column->precision) ? '' : "({$column->precision})") . ' with time zone';
    }
    protected function typeTimestamp(Fluent $column)
    {
        if ($column->useCurrent) {
            $column->default(new Expression('CURRENT_TIMESTAMP'));
        }
        return 'timestamp' . (is_null($column->precision) ? '' : "({$column->precision})") . ' without time zone';
    }
    protected function typeTimestampTz(Fluent $column)
    {
        if ($column->useCurrent) {
            $column->default(new Expression('CURRENT_TIMESTAMP'));
        }
        return 'timestamp' . (is_null($column->precision) ? '' : "({$column->precision})") . ' with time zone';
    }
    protected function typeYear(Fluent $column)
    {
        return $this->typeInteger($column);
    }
    protected function typeBinary(Fluent $column)
    {
        return 'bytea';
    }
    protected function typeUuid(Fluent $column)
    {
        return 'uuid';
    }
    protected function typeIpAddress(Fluent $column)
    {
        return 'inet';
    }
    protected function typeMacAddress(Fluent $column)
    {
        return 'macaddr';
    }
    protected function typeGeometry(Fluent $column)
    {
        return $this->formatPostGisType('geometry', $column);
    }
    protected function typePoint(Fluent $column)
    {
        return $this->formatPostGisType('point', $column);
    }
    protected function typeLineString(Fluent $column)
    {
        return $this->formatPostGisType('linestring', $column);
    }
    protected function typePolygon(Fluent $column)
    {
        return $this->formatPostGisType('polygon', $column);
    }
    protected function typeGeometryCollection(Fluent $column)
    {
        return $this->formatPostGisType('geometrycollection', $column);
    }
    protected function typeMultiPoint(Fluent $column)
    {
        return $this->formatPostGisType('multipoint', $column);
    }
    public function typeMultiLineString(Fluent $column)
    {
        return $this->formatPostGisType('multilinestring', $column);
    }
    protected function typeMultiPolygon(Fluent $column)
    {
        return $this->formatPostGisType('multipolygon', $column);
    }
    protected function typeMultiPolygonZ(Fluent $column)
    {
        return $this->formatPostGisType('multipolygonz', $column);
    }
    private function formatPostGisType($type, Fluent $column)
    {
        if ($column->isGeometry === null) {
            return sprintf('geography(%s, %s)', $type, $column->projection ?? '4326');
        }
        if ($column->projection !== null) {
            return sprintf('geometry(%s, %s)', $type, $column->projection);
        }
        return "geometry({$type})";
    }
    protected function modifyCollate(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->collation)) {
            return ' collate ' . $this->wrapValue($column->collation);
        }
    }
    protected function modifyNullable(Blueprint $blueprint, Fluent $column)
    {
        if ($column->change) {
            return $column->nullable ? 'drop not null' : 'set not null';
        }
        return $column->nullable ? ' null' : ' not null';
    }
    protected function modifyDefault(Blueprint $blueprint, Fluent $column)
    {
        if ($column->change) {
            return is_null($column->default) ? 'drop default' : 'set default ' . $this->getDefaultValue($column->default);
        }
        if (!is_null($column->default)) {
            return ' default ' . $this->getDefaultValue($column->default);
        }
    }
    protected function modifyIncrement(Blueprint $blueprint, Fluent $column)
    {
        if (!$column->change && (in_array($column->type, $this->serials) || $column->generatedAs !== null) && $column->autoIncrement) {
            return ' primary key';
        }
    }
    protected function modifyVirtualAs(Blueprint $blueprint, Fluent $column)
    {
        if ($column->change) {
            if (array_key_exists('virtualAs', $column->getAttributes())) {
                return is_null($column->virtualAs) ? 'drop expression if exists' : throw new LogicException('This database driver does not support modifying generated columns.');
            }
            return null;
        }
        if (!is_null($column->virtualAs)) {
            return " generated always as ({$this->getValue($column->virtualAs)})";
        }
    }
    protected function modifyStoredAs(Blueprint $blueprint, Fluent $column)
    {
        if ($column->change) {
            if (array_key_exists('storedAs', $column->getAttributes())) {
                return is_null($column->storedAs) ? 'drop expression if exists' : throw new LogicException('This database driver does not support modifying generated columns.');
            }
            return null;
        }
        if (!is_null($column->storedAs)) {
            return " generated always as ({$this->getValue($column->storedAs)}) stored";
        }
    }
    protected function modifyGeneratedAs(Blueprint $blueprint, Fluent $column)
    {
        $sql = null;
        if (!is_null($column->generatedAs)) {
            $sql = sprintf(' generated %s as identity%s', $column->always ? 'always' : 'by default', !is_bool($column->generatedAs) && !empty($column->generatedAs) ? " ({$column->generatedAs})" : '');
        }
        if ($column->change) {
            $changes = ['drop identity if exists'];
            if (!is_null($sql)) {
                $changes[] = 'add ' . $sql;
            }
            return $changes;
        }
        return $sql;
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use Doctrine\DBAL\Schema\Index;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Arr;
use Illuminate\Support\Fluent;
use RuntimeException;
class SQLiteGrammar extends Grammar
{
    protected $modifiers = ['Increment', 'Nullable', 'Default', 'VirtualAs', 'StoredAs'];
    protected $serials = ['bigInteger', 'integer', 'mediumInteger', 'smallInteger', 'tinyInteger'];
    public function compileTableExists()
    {
        return "select * from sqlite_master where type = 'table' and name = ?";
    }
    public function compileDbstatExists()
    {
        return "select exists (select 1 from pragma_compile_options where compile_options = 'ENABLE_DBSTAT_VTAB') as enabled";
    }
    public function compileTables($withSize = false)
    {
        return $withSize ? 'select m.tbl_name as name, sum(s.pgsize) as size from sqlite_master as m ' . 'join dbstat as s on s.name = m.name ' . "where m.type in ('table', 'index') and m.tbl_name not like 'sqlite_%' " . 'group by m.tbl_name ' . 'order by m.tbl_name' : "select name from sqlite_master where type = 'table' and name not like 'sqlite_%' order by name";
    }
    public function compileViews()
    {
        return "select name, sql as definition from sqlite_master where type = 'view' order by name";
    }
    public function compileGetAllTables()
    {
        return 'select type, name from sqlite_master where type = \'table\' and name not like \'sqlite_%\'';
    }
    public function compileGetAllViews()
    {
        return 'select type, name from sqlite_master where type = \'view\'';
    }
    public function compileColumnListing($table)
    {
        return 'pragma table_info(' . $this->wrap(str_replace('.', '__', $table)) . ')';
    }
    public function compileColumns($table)
    {
        return sprintf('select name, type, not "notnull" as "nullable", dflt_value as "default", pk as "primary" ' . 'from pragma_table_info(%s) order by cid asc', $this->quoteString(str_replace('.', '__', $table)));
    }
    public function compileIndexes($table)
    {
        return sprintf('select \'primary\' as name, group_concat(col) as columns, 1 as "unique", 1 as "primary" ' . 'from (select name as col from pragma_table_info(%s) where pk > 0 order by pk, cid) group by name ' . 'union select name, group_concat(col) as columns, "unique", origin = \'pk\' as "primary" ' . 'from (select il.*, ii.name as col from pragma_index_list(%s) il, pragma_index_info(il.name) ii order by il.seq, ii.seqno) ' . 'group by name, "unique", "primary"', $table = $this->quoteString(str_replace('.', '__', $table)), $table);
    }
    public function compileForeignKeys($table)
    {
        return sprintf('select group_concat("from") as columns, "table" as foreign_table, ' . 'group_concat("to") as foreign_columns, on_update, on_delete ' . 'from (select * from pragma_foreign_key_list(%s) order by id desc, seq) ' . 'group by id, "table", on_update, on_delete', $this->quoteString(str_replace('.', '__', $table)));
    }
    public function compileCreate(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('%s table %s (%s%s%s)', $blueprint->temporary ? 'create temporary' : 'create', $this->wrapTable($blueprint), implode(', ', $this->getColumns($blueprint)), (string) $this->addForeignKeys($blueprint), (string) $this->addPrimaryKeys($blueprint));
    }
    protected function addForeignKeys(Blueprint $blueprint)
    {
        $foreigns = $this->getCommandsByName($blueprint, 'foreign');
        return collect($foreigns)->reduce(function ($sql, $foreign) {
            $sql .= $this->getForeignKey($foreign);
            if (!is_null($foreign->onDelete)) {
                $sql .= " on delete {$foreign->onDelete}";
            }
            if (!is_null($foreign->onUpdate)) {
                $sql .= " on update {$foreign->onUpdate}";
            }
            return $sql;
        }, '');
    }
    protected function getForeignKey($foreign)
    {
        return sprintf(', foreign key(%s) references %s(%s)', $this->columnize($foreign->columns), $this->wrapTable($foreign->on), $this->columnize((array) $foreign->references));
    }
    protected function addPrimaryKeys(Blueprint $blueprint)
    {
        if (!is_null($primary = $this->getCommandByName($blueprint, 'primary'))) {
            return ", primary key ({$this->columnize($primary->columns)})";
        }
    }
    public function compileAdd(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->prefixArray('add column', $this->getColumns($blueprint));
        return collect($columns)->reject(function ($column) {
            return preg_match('/as \(.*\) stored/', $column) > 0;
        })->map(function ($column) use ($blueprint) {
            return 'alter table ' . $this->wrapTable($blueprint) . ' ' . $column;
        })->all();
    }
    public function compileRenameColumn(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        return $connection->usingNativeSchemaOperations() ? sprintf('alter table %s rename column %s to %s', $this->wrapTable($blueprint), $this->wrap($command->from), $this->wrap($command->to)) : parent::compileRenameColumn($blueprint, $command, $connection);
    }
    public function compileUnique(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('create unique index %s on %s (%s)', $this->wrap($command->index), $this->wrapTable($blueprint), $this->columnize($command->columns));
    }
    public function compileIndex(Blueprint $blueprint, Fluent $command)
    {
        return sprintf('create index %s on %s (%s)', $this->wrap($command->index), $this->wrapTable($blueprint), $this->columnize($command->columns));
    }
    public function compileSpatialIndex(Blueprint $blueprint, Fluent $command)
    {
        throw new RuntimeException('The database driver in use does not support spatial indexes.');
    }
    public function compileForeign(Blueprint $blueprint, Fluent $command)
    {
    }
    public function compileDrop(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table ' . $this->wrapTable($blueprint);
    }
    public function compileDropIfExists(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table if exists ' . $this->wrapTable($blueprint);
    }
    public function compileDropAllTables()
    {
        return "delete from sqlite_master where type in ('table', 'index', 'trigger')";
    }
    public function compileDropAllViews()
    {
        return "delete from sqlite_master where type in ('view')";
    }
    public function compileRebuild()
    {
        return 'vacuum';
    }
    public function compileDropColumn(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        if ($connection->usingNativeSchemaOperations()) {
            $table = $this->wrapTable($blueprint);
            $columns = $this->prefixArray('drop column', $this->wrapArray($command->columns));
            return collect($columns)->map(fn($column) => 'alter table ' . $table . ' ' . $column)->all();
        } else {
            $tableDiff = $this->getDoctrineTableDiff($blueprint, $schema = $connection->getDoctrineSchemaManager());
            foreach ($command->columns as $name) {
                $tableDiff->removedColumns[$name] = $connection->getDoctrineColumn($this->getTablePrefix() . $blueprint->getTable(), $name);
            }
            return (array) $schema->getDatabasePlatform()->getAlterTableSQL($tableDiff);
        }
    }
    public function compileDropUnique(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "drop index {$index}";
    }
    public function compileDropIndex(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "drop index {$index}";
    }
    public function compileDropSpatialIndex(Blueprint $blueprint, Fluent $command)
    {
        throw new RuntimeException('The database driver in use does not support spatial indexes.');
    }
    public function compileRename(Blueprint $blueprint, Fluent $command)
    {
        $from = $this->wrapTable($blueprint);
        return "alter table {$from} rename to " . $this->wrapTable($command->to);
    }
    public function compileRenameIndex(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        $schemaManager = $connection->getDoctrineSchemaManager();
        $indexes = $schemaManager->listTableIndexes($this->getTablePrefix() . $blueprint->getTable());
        $index = Arr::get($indexes, $command->from);
        if (!$index) {
            throw new RuntimeException("Index [{$command->from}] does not exist.");
        }
        $newIndex = new Index($command->to, $index->getColumns(), $index->isUnique(), $index->isPrimary(), $index->getFlags(), $index->getOptions());
        $platform = $connection->getDoctrineConnection()->getDatabasePlatform();
        return [$platform->getDropIndexSQL($command->from, $this->getTablePrefix() . $blueprint->getTable()), $platform->getCreateIndexSQL($newIndex, $this->getTablePrefix() . $blueprint->getTable())];
    }
    public function compileEnableForeignKeyConstraints()
    {
        return 'PRAGMA foreign_keys = ON;';
    }
    public function compileDisableForeignKeyConstraints()
    {
        return 'PRAGMA foreign_keys = OFF;';
    }
    public function compileEnableWriteableSchema()
    {
        return 'PRAGMA writable_schema = 1;';
    }
    public function compileDisableWriteableSchema()
    {
        return 'PRAGMA writable_schema = 0;';
    }
    protected function typeChar(Fluent $column)
    {
        return 'varchar';
    }
    protected function typeString(Fluent $column)
    {
        return 'varchar';
    }
    protected function typeTinyText(Fluent $column)
    {
        return 'text';
    }
    protected function typeText(Fluent $column)
    {
        return 'text';
    }
    protected function typeMediumText(Fluent $column)
    {
        return 'text';
    }
    protected function typeLongText(Fluent $column)
    {
        return 'text';
    }
    protected function typeInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeBigInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeMediumInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeTinyInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeSmallInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeFloat(Fluent $column)
    {
        return 'float';
    }
    protected function typeDouble(Fluent $column)
    {
        return 'float';
    }
    protected function typeDecimal(Fluent $column)
    {
        return 'numeric';
    }
    protected function typeBoolean(Fluent $column)
    {
        return 'tinyint(1)';
    }
    protected function typeEnum(Fluent $column)
    {
        return sprintf('varchar check ("%s" in (%s))', $column->name, $this->quoteString($column->allowed));
    }
    protected function typeJson(Fluent $column)
    {
        return 'text';
    }
    protected function typeJsonb(Fluent $column)
    {
        return 'text';
    }
    protected function typeDate(Fluent $column)
    {
        return 'date';
    }
    protected function typeDateTime(Fluent $column)
    {
        return $this->typeTimestamp($column);
    }
    protected function typeDateTimeTz(Fluent $column)
    {
        return $this->typeDateTime($column);
    }
    protected function typeTime(Fluent $column)
    {
        return 'time';
    }
    protected function typeTimeTz(Fluent $column)
    {
        return $this->typeTime($column);
    }
    protected function typeTimestamp(Fluent $column)
    {
        if ($column->useCurrent) {
            $column->default(new Expression('CURRENT_TIMESTAMP'));
        }
        return 'datetime';
    }
    protected function typeTimestampTz(Fluent $column)
    {
        return $this->typeTimestamp($column);
    }
    protected function typeYear(Fluent $column)
    {
        return $this->typeInteger($column);
    }
    protected function typeBinary(Fluent $column)
    {
        return 'blob';
    }
    protected function typeUuid(Fluent $column)
    {
        return 'varchar';
    }
    protected function typeIpAddress(Fluent $column)
    {
        return 'varchar';
    }
    protected function typeMacAddress(Fluent $column)
    {
        return 'varchar';
    }
    public function typeGeometry(Fluent $column)
    {
        return 'geometry';
    }
    public function typePoint(Fluent $column)
    {
        return 'point';
    }
    public function typeLineString(Fluent $column)
    {
        return 'linestring';
    }
    public function typePolygon(Fluent $column)
    {
        return 'polygon';
    }
    public function typeGeometryCollection(Fluent $column)
    {
        return 'geometrycollection';
    }
    public function typeMultiPoint(Fluent $column)
    {
        return 'multipoint';
    }
    public function typeMultiLineString(Fluent $column)
    {
        return 'multilinestring';
    }
    public function typeMultiPolygon(Fluent $column)
    {
        return 'multipolygon';
    }
    protected function typeComputed(Fluent $column)
    {
        throw new RuntimeException('This database driver requires a type, see the virtualAs / storedAs modifiers.');
    }
    protected function modifyVirtualAs(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($virtualAs = $column->virtualAsJson)) {
            if ($this->isJsonSelector($virtualAs)) {
                $virtualAs = $this->wrapJsonSelector($virtualAs);
            }
            return " as ({$virtualAs})";
        }
        if (!is_null($virtualAs = $column->virtualAs)) {
            return " as ({$this->getValue($virtualAs)})";
        }
    }
    protected function modifyStoredAs(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($storedAs = $column->storedAsJson)) {
            if ($this->isJsonSelector($storedAs)) {
                $storedAs = $this->wrapJsonSelector($storedAs);
            }
            return " as ({$storedAs}) stored";
        }
        if (!is_null($storedAs = $column->storedAs)) {
            return " as ({$this->getValue($column->storedAs)}) stored";
        }
    }
    protected function modifyNullable(Blueprint $blueprint, Fluent $column)
    {
        if (is_null($column->virtualAs) && is_null($column->virtualAsJson) && is_null($column->storedAs) && is_null($column->storedAsJson)) {
            return $column->nullable ? '' : ' not null';
        }
        if ($column->nullable === false) {
            return ' not null';
        }
    }
    protected function modifyDefault(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->default) && is_null($column->virtualAs) && is_null($column->virtualAsJson) && is_null($column->storedAs)) {
            return ' default ' . $this->getDefaultValue($column->default);
        }
    }
    protected function modifyIncrement(Blueprint $blueprint, Fluent $column)
    {
        if (in_array($column->type, $this->serials) && $column->autoIncrement) {
            return ' primary key autoincrement';
        }
    }
    protected function wrapJsonSelector($value)
    {
        [$field, $path] = $this->wrapJsonFieldAndPath($value);
        return 'json_extract(' . $field . $path . ')';
    }
}
}

namespace Illuminate\Database\Schema {
class MySqlBuilder extends Builder
{
    public function createDatabase($name)
    {
        return $this->connection->statement($this->grammar->compileCreateDatabase($name, $this->connection));
    }
    public function dropDatabaseIfExists($name)
    {
        return $this->connection->statement($this->grammar->compileDropDatabaseIfExists($name));
    }
    public function getTables()
    {
        return $this->connection->getPostProcessor()->processTables($this->connection->selectFromWriteConnection($this->grammar->compileTables($this->connection->getDatabaseName())));
    }
    public function getViews()
    {
        return $this->connection->getPostProcessor()->processViews($this->connection->selectFromWriteConnection($this->grammar->compileViews($this->connection->getDatabaseName())));
    }
    public function getAllTables()
    {
        return $this->connection->select($this->grammar->compileGetAllTables());
    }
    public function getAllViews()
    {
        return $this->connection->select($this->grammar->compileGetAllViews());
    }
    public function getColumns($table)
    {
        $table = $this->connection->getTablePrefix() . $table;
        $results = $this->connection->selectFromWriteConnection($this->grammar->compileColumns($this->connection->getDatabaseName(), $table));
        return $this->connection->getPostProcessor()->processColumns($results);
    }
    public function getIndexes($table)
    {
        $table = $this->connection->getTablePrefix() . $table;
        return $this->connection->getPostProcessor()->processIndexes($this->connection->selectFromWriteConnection($this->grammar->compileIndexes($this->connection->getDatabaseName(), $table)));
    }
    public function getForeignKeys($table)
    {
        $table = $this->connection->getTablePrefix() . $table;
        return $this->connection->getPostProcessor()->processForeignKeys($this->connection->selectFromWriteConnection($this->grammar->compileForeignKeys($this->connection->getDatabaseName(), $table)));
    }
    public function dropAllTables()
    {
        $tables = array_column($this->getTables(), 'name');
        if (empty($tables)) {
            return;
        }
        $this->disableForeignKeyConstraints();
        $this->connection->statement($this->grammar->compileDropAllTables($tables));
        $this->enableForeignKeyConstraints();
    }
    public function dropAllViews()
    {
        $views = array_column($this->getViews(), 'name');
        if (empty($views)) {
            return;
        }
        $this->connection->statement($this->grammar->compileDropAllViews($views));
    }
}
}

namespace Illuminate\Database\Schema {
use Illuminate\Database\Concerns\ParsesSearchPath;
class PostgresBuilder extends Builder
{
    use ParsesSearchPath {
        parseSearchPath as baseParseSearchPath;
    }
    public function createDatabase($name)
    {
        return $this->connection->statement($this->grammar->compileCreateDatabase($name, $this->connection));
    }
    public function dropDatabaseIfExists($name)
    {
        return $this->connection->statement($this->grammar->compileDropDatabaseIfExists($name));
    }
    public function hasTable($table)
    {
        [$database, $schema, $table] = $this->parseSchemaAndTable($table);
        $table = $this->connection->getTablePrefix() . $table;
        return count($this->connection->selectFromWriteConnection($this->grammar->compileTableExists(), [$database, $schema, $table])) > 0;
    }
    public function getTypes()
    {
        return $this->connection->getPostProcessor()->processTypes($this->connection->selectFromWriteConnection($this->grammar->compileTypes()));
    }
    public function getAllTables()
    {
        return $this->connection->select($this->grammar->compileGetAllTables($this->parseSearchPath($this->connection->getConfig('search_path') ?: $this->connection->getConfig('schema'))));
    }
    public function getAllViews()
    {
        return $this->connection->select($this->grammar->compileGetAllViews($this->parseSearchPath($this->connection->getConfig('search_path') ?: $this->connection->getConfig('schema'))));
    }
    public function dropAllTables()
    {
        $tables = [];
        $excludedTables = $this->grammar->escapeNames($this->connection->getConfig('dont_drop') ?? ['spatial_ref_sys']);
        $schemas = $this->grammar->escapeNames($this->getSchemas());
        foreach ($this->getTables() as $table) {
            $qualifiedName = $table['schema'] . '.' . $table['name'];
            if (empty(array_intersect($this->grammar->escapeNames([$table['name'], $qualifiedName]), $excludedTables)) && in_array($this->grammar->escapeNames([$table['schema']])[0], $schemas)) {
                $tables[] = $qualifiedName;
            }
        }
        if (empty($tables)) {
            return;
        }
        $this->connection->statement($this->grammar->compileDropAllTables($tables));
    }
    public function dropAllViews()
    {
        $views = [];
        $schemas = $this->grammar->escapeNames($this->getSchemas());
        foreach ($this->getViews() as $view) {
            if (in_array($this->grammar->escapeNames([$view['schema']])[0], $schemas)) {
                $views[] = $view['schema'] . '.' . $view['name'];
            }
        }
        if (empty($views)) {
            return;
        }
        $this->connection->statement($this->grammar->compileDropAllViews($views));
    }
    public function getAllTypes()
    {
        return $this->connection->select($this->grammar->compileGetAllTypes());
    }
    public function dropAllTypes()
    {
        $types = [];
        $domains = [];
        $schemas = $this->grammar->escapeNames($this->getSchemas());
        foreach ($this->getTypes() as $type) {
            if (!$type['implicit'] && in_array($this->grammar->escapeNames([$type['schema']])[0], $schemas)) {
                if ($type['type'] === 'domain') {
                    $domains[] = $type['schema'] . '.' . $type['name'];
                } else {
                    $types[] = $type['schema'] . '.' . $type['name'];
                }
            }
        }
        if (!empty($types)) {
            $this->connection->statement($this->grammar->compileDropAllTypes($types));
        }
        if (!empty($domains)) {
            $this->connection->statement($this->grammar->compileDropAllDomains($domains));
        }
    }
    public function getColumns($table)
    {
        [$database, $schema, $table] = $this->parseSchemaAndTable($table);
        $table = $this->connection->getTablePrefix() . $table;
        $results = $this->connection->selectFromWriteConnection($this->grammar->compileColumns($database, $schema, $table));
        return $this->connection->getPostProcessor()->processColumns($results);
    }
    public function getIndexes($table)
    {
        [, $schema, $table] = $this->parseSchemaAndTable($table);
        $table = $this->connection->getTablePrefix() . $table;
        return $this->connection->getPostProcessor()->processIndexes($this->connection->selectFromWriteConnection($this->grammar->compileIndexes($schema, $table)));
    }
    public function getForeignKeys($table)
    {
        [, $schema, $table] = $this->parseSchemaAndTable($table);
        $table = $this->connection->getTablePrefix() . $table;
        return $this->connection->getPostProcessor()->processForeignKeys($this->connection->selectFromWriteConnection($this->grammar->compileForeignKeys($schema, $table)));
    }
    protected function getSchemas()
    {
        return $this->parseSearchPath(($this->connection->getConfig('search_path') ?: $this->connection->getConfig('schema')) ?: 'public');
    }
    protected function parseSchemaAndTable($reference)
    {
        $parts = explode('.', $reference);
        $database = $this->connection->getConfig('database');
        if (count($parts) === 3) {
            $database = $parts[0];
            array_shift($parts);
        }
        $schema = $this->getSchemas()[0];
        if (count($parts) === 2) {
            $schema = $parts[0];
            array_shift($parts);
        }
        return [$database, $schema, $parts[0]];
    }
    protected function parseSearchPath($searchPath)
    {
        return array_map(function ($schema) {
            return $schema === '$user' ? $this->connection->getConfig('username') : $schema;
        }, $this->baseParseSearchPath($searchPath));
    }
}
}

namespace Illuminate\Database {
interface ConnectionResolverInterface
{
    public function connection($name = null);
    public function getDefaultConnection();
    public function setDefaultConnection($name);
}
}

namespace Illuminate\Database\Capsule {
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model as Eloquent;
use Illuminate\Support\Traits\CapsuleManagerTrait;
use PDO;
class Manager
{
    use CapsuleManagerTrait;
    protected $manager;
    public function __construct(?Container $container = null)
    {
        $this->setupContainer($container ?: new Container());
        $this->setupDefaultConfiguration();
        $this->setupManager();
    }
    protected function setupDefaultConfiguration()
    {
        $this->container['config']['database.fetch'] = PDO::FETCH_OBJ;
        $this->container['config']['database.default'] = 'default';
    }
    protected function setupManager()
    {
        $factory = new ConnectionFactory($this->container);
        $this->manager = new DatabaseManager($this->container, $factory);
    }
    public static function connection($connection = null)
    {
        return static::$instance->getConnection($connection);
    }
    public static function table($table, $as = null, $connection = null)
    {
        return static::$instance->connection($connection)->table($table, $as);
    }
    public static function schema($connection = null)
    {
        return static::$instance->connection($connection)->getSchemaBuilder();
    }
    public function getConnection($name = null)
    {
        return $this->manager->connection($name);
    }
    public function addConnection(array $config, $name = 'default')
    {
        $connections = $this->container['config']['database.connections'];
        $connections[$name] = $config;
        $this->container['config']['database.connections'] = $connections;
    }
    public function bootEloquent()
    {
        Eloquent::setConnectionResolver($this->manager);
        if ($dispatcher = $this->getEventDispatcher()) {
            Eloquent::setEventDispatcher($dispatcher);
        }
    }
    public function setFetchMode($fetchMode)
    {
        $this->container['config']['database.fetch'] = $fetchMode;
        return $this;
    }
    public function getDatabaseManager()
    {
        return $this->manager;
    }
    public function getEventDispatcher()
    {
        if ($this->container->bound('events')) {
            return $this->container['events'];
        }
    }
    public function setEventDispatcher(Dispatcher $dispatcher)
    {
        $this->container->instance('events', $dispatcher);
    }
    public static function __callStatic($method, $parameters)
    {
        return static::connection()->{$method}(...$parameters);
    }
}
}

namespace Illuminate\Database {
use Closure;
use Exception;
use Illuminate\Database\PDO\SqlServerDriver;
use Illuminate\Database\Query\Grammars\SqlServerGrammar as QueryGrammar;
use Illuminate\Database\Query\Processors\SqlServerProcessor;
use Illuminate\Database\Schema\Grammars\SqlServerGrammar as SchemaGrammar;
use Illuminate\Database\Schema\SqlServerBuilder;
use Illuminate\Filesystem\Filesystem;
use RuntimeException;
use Throwable;
class SqlServerConnection extends Connection
{
    public function transaction(Closure $callback, $attempts = 1)
    {
        for ($a = 1; $a <= $attempts; $a++) {
            if ($this->getDriverName() === 'sqlsrv') {
                return parent::transaction($callback, $attempts);
            }
            $this->getPdo()->exec('BEGIN TRAN');
            try {
                $result = $callback($this);
                $this->getPdo()->exec('COMMIT TRAN');
            } catch (Throwable $e) {
                $this->getPdo()->exec('ROLLBACK TRAN');
                throw $e;
            }
            return $result;
        }
    }
    protected function escapeBinary($value)
    {
        $hex = bin2hex($value);
        return "0x{$hex}";
    }
    protected function isUniqueConstraintError(Exception $exception)
    {
        return boolval(preg_match('#Cannot insert duplicate key row in object#i', $exception->getMessage()));
    }
    protected function getDefaultQueryGrammar()
    {
        ($grammar = new QueryGrammar())->setConnection($this);
        return $this->withTablePrefix($grammar);
    }
    public function getSchemaBuilder()
    {
        if (is_null($this->schemaGrammar)) {
            $this->useDefaultSchemaGrammar();
        }
        return new SqlServerBuilder($this);
    }
    protected function getDefaultSchemaGrammar()
    {
        ($grammar = new SchemaGrammar())->setConnection($this);
        return $this->withTablePrefix($grammar);
    }
    public function getSchemaState(?Filesystem $files = null, ?callable $processFactory = null)
    {
        throw new RuntimeException('Schema dumping is not supported when using SQL Server.');
    }
    protected function getDefaultPostProcessor()
    {
        return new SqlServerProcessor();
    }
    protected function getDoctrineDriver()
    {
        return new SqlServerDriver();
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use BadMethodCallException;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Concerns\InteractsWithDictionary;
class MorphTo extends BelongsTo
{
    use InteractsWithDictionary;
    protected $morphType;
    protected $models;
    protected $dictionary = [];
    protected $macroBuffer = [];
    protected $morphableEagerLoads = [];
    protected $morphableEagerLoadCounts = [];
    protected $morphableConstraints = [];
    public function __construct(Builder $query, Model $parent, $foreignKey, $ownerKey, $type, $relation)
    {
        $this->morphType = $type;
        parent::__construct($query, $parent, $foreignKey, $ownerKey, $relation);
    }
    public function addEagerConstraints(array $models)
    {
        $this->buildDictionary($this->models = Collection::make($models));
    }
    protected function buildDictionary(Collection $models)
    {
        foreach ($models as $model) {
            if ($model->{$this->morphType}) {
                $morphTypeKey = $this->getDictionaryKey($model->{$this->morphType});
                $foreignKeyKey = $this->getDictionaryKey($model->{$this->foreignKey});
                $this->dictionary[$morphTypeKey][$foreignKeyKey][] = $model;
            }
        }
    }
    public function getEager()
    {
        foreach (array_keys($this->dictionary) as $type) {
            $this->matchToMorphParents($type, $this->getResultsByType($type));
        }
        return $this->models;
    }
    protected function getResultsByType($type)
    {
        $instance = $this->createModelByType($type);
        $ownerKey = $this->ownerKey ?? $instance->getKeyName();
        $query = $this->replayMacros($instance->newQuery())->mergeConstraintsFrom($this->getQuery())->with(array_merge($this->getQuery()->getEagerLoads(), (array) ($this->morphableEagerLoads[get_class($instance)] ?? [])))->withCount((array) ($this->morphableEagerLoadCounts[get_class($instance)] ?? []));
        if ($callback = $this->morphableConstraints[get_class($instance)] ?? null) {
            $callback($query);
        }
        $whereIn = $this->whereInMethod($instance, $ownerKey);
        return $query->{$whereIn}($instance->getTable() . '.' . $ownerKey, $this->gatherKeysByType($type, $instance->getKeyType()))->get();
    }
    protected function gatherKeysByType($type, $keyType)
    {
        return $keyType !== 'string' ? array_keys($this->dictionary[$type]) : array_map(function ($modelId) {
            return (string) $modelId;
        }, array_filter(array_keys($this->dictionary[$type])));
    }
    public function createModelByType($type)
    {
        $class = Model::getActualClassNameForMorph($type);
        return tap(new $class(), function ($instance) {
            if (!$instance->getConnectionName()) {
                $instance->setConnection($this->getConnection()->getName());
            }
        });
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $models;
    }
    protected function matchToMorphParents($type, Collection $results)
    {
        foreach ($results as $result) {
            $ownerKey = !is_null($this->ownerKey) ? $this->getDictionaryKey($result->{$this->ownerKey}) : $result->getKey();
            if (isset($this->dictionary[$type][$ownerKey])) {
                foreach ($this->dictionary[$type][$ownerKey] as $model) {
                    $model->setRelation($this->relationName, $result);
                }
            }
        }
    }
    public function associate($model)
    {
        if ($model instanceof Model) {
            $foreignKey = $this->ownerKey && $model->{$this->ownerKey} ? $this->ownerKey : $model->getKeyName();
        }
        $this->parent->setAttribute($this->foreignKey, $model instanceof Model ? $model->{$foreignKey} : null);
        $this->parent->setAttribute($this->morphType, $model instanceof Model ? $model->getMorphClass() : null);
        return $this->parent->setRelation($this->relationName, $model);
    }
    public function dissociate()
    {
        $this->parent->setAttribute($this->foreignKey, null);
        $this->parent->setAttribute($this->morphType, null);
        return $this->parent->setRelation($this->relationName, null);
    }
    public function touch()
    {
        if (!is_null($this->child->{$this->foreignKey})) {
            parent::touch();
        }
    }
    protected function newRelatedInstanceFor(Model $parent)
    {
        return $parent->{$this->getRelationName()}()->getRelated()->newInstance();
    }
    public function getMorphType()
    {
        return $this->morphType;
    }
    public function getDictionary()
    {
        return $this->dictionary;
    }
    public function morphWith(array $with)
    {
        $this->morphableEagerLoads = array_merge($this->morphableEagerLoads, $with);
        return $this;
    }
    public function morphWithCount(array $withCount)
    {
        $this->morphableEagerLoadCounts = array_merge($this->morphableEagerLoadCounts, $withCount);
        return $this;
    }
    public function constrain(array $callbacks)
    {
        $this->morphableConstraints = array_merge($this->morphableConstraints, $callbacks);
        return $this;
    }
    public function withTrashed()
    {
        $callback = fn($query) => $query->hasMacro('withTrashed') ? $query->withTrashed() : $query;
        $this->macroBuffer[] = ['method' => 'when', 'parameters' => [true, $callback]];
        return $this->when(true, $callback);
    }
    public function withoutTrashed()
    {
        $callback = fn($query) => $query->hasMacro('withoutTrashed') ? $query->withoutTrashed() : $query;
        $this->macroBuffer[] = ['method' => 'when', 'parameters' => [true, $callback]];
        return $this->when(true, $callback);
    }
    public function onlyTrashed()
    {
        $callback = fn($query) => $query->hasMacro('onlyTrashed') ? $query->onlyTrashed() : $query;
        $this->macroBuffer[] = ['method' => 'when', 'parameters' => [true, $callback]];
        return $this->when(true, $callback);
    }
    protected function replayMacros(Builder $query)
    {
        foreach ($this->macroBuffer as $macro) {
            $query->{$macro['method']}(...$macro['parameters']);
        }
        return $query;
    }
    public function __call($method, $parameters)
    {
        try {
            $result = parent::__call($method, $parameters);
            if (in_array($method, ['select', 'selectRaw', 'selectSub', 'addSelect', 'withoutGlobalScopes'])) {
                $this->macroBuffer[] = compact('method', 'parameters');
            }
            return $result;
        } catch (BadMethodCallException) {
            $this->macroBuffer[] = compact('method', 'parameters');
            return $this;
        }
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Closure;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\Eloquent\Relations\Concerns\InteractsWithDictionary;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\UniqueConstraintViolationException;
class HasManyThrough extends Relation
{
    use InteractsWithDictionary;
    protected $throughParent;
    protected $farParent;
    protected $firstKey;
    protected $secondKey;
    protected $localKey;
    protected $secondLocalKey;
    public function __construct(Builder $query, Model $farParent, Model $throughParent, $firstKey, $secondKey, $localKey, $secondLocalKey)
    {
        $this->localKey = $localKey;
        $this->firstKey = $firstKey;
        $this->secondKey = $secondKey;
        $this->farParent = $farParent;
        $this->throughParent = $throughParent;
        $this->secondLocalKey = $secondLocalKey;
        parent::__construct($query, $throughParent);
    }
    public function one()
    {
        return HasOneThrough::noConstraints(fn() => new HasOneThrough($this->getQuery(), $this->farParent, $this->throughParent, $this->getFirstKeyName(), $this->secondKey, $this->getLocalKeyName(), $this->getSecondLocalKeyName()));
    }
    public function addConstraints()
    {
        $localValue = $this->farParent[$this->localKey];
        $this->performJoin();
        if (static::$constraints) {
            $this->query->where($this->getQualifiedFirstKeyName(), '=', $localValue);
        }
    }
    protected function performJoin(?Builder $query = null)
    {
        $query = $query ?: $this->query;
        $farKey = $this->getQualifiedFarKeyName();
        $query->join($this->throughParent->getTable(), $this->getQualifiedParentKeyName(), '=', $farKey);
        if ($this->throughParentSoftDeletes()) {
            $query->withGlobalScope('SoftDeletableHasManyThrough', function ($query) {
                $query->whereNull($this->throughParent->getQualifiedDeletedAtColumn());
            });
        }
    }
    public function getQualifiedParentKeyName()
    {
        return $this->parent->qualifyColumn($this->secondLocalKey);
    }
    public function throughParentSoftDeletes()
    {
        return in_array(SoftDeletes::class, class_uses_recursive($this->throughParent));
    }
    public function withTrashedParents()
    {
        $this->query->withoutGlobalScope('SoftDeletableHasManyThrough');
        return $this;
    }
    public function addEagerConstraints(array $models)
    {
        $whereIn = $this->whereInMethod($this->farParent, $this->localKey);
        $this->whereInEager($whereIn, $this->getQualifiedFirstKeyName(), $this->getKeys($models, $this->localKey));
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->related->newCollection());
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        $dictionary = $this->buildDictionary($results);
        foreach ($models as $model) {
            if (isset($dictionary[$key = $this->getDictionaryKey($model->getAttribute($this->localKey))])) {
                $model->setRelation($relation, $this->related->newCollection($dictionary[$key]));
            }
        }
        return $models;
    }
    protected function buildDictionary(Collection $results)
    {
        $dictionary = [];
        foreach ($results as $result) {
            $dictionary[$result->laravel_through_key][] = $result;
        }
        return $dictionary;
    }
    public function firstOrNew(array $attributes = [], array $values = [])
    {
        if (!is_null($instance = $this->where($attributes)->first())) {
            return $instance;
        }
        return $this->related->newInstance(array_merge($attributes, $values));
    }
    public function firstOrCreate(array $attributes = [], array $values = [])
    {
        if (!is_null($instance = (clone $this)->where($attributes)->first())) {
            return $instance;
        }
        return $this->createOrFirst(array_merge($attributes, $values));
    }
    public function createOrFirst(array $attributes = [], array $values = [])
    {
        try {
            return $this->getQuery()->withSavepointIfNeeded(fn() => $this->create(array_merge($attributes, $values)));
        } catch (UniqueConstraintViolationException $exception) {
            return $this->where($attributes)->first() ?? throw $exception;
        }
    }
    public function updateOrCreate(array $attributes, array $values = [])
    {
        return tap($this->firstOrCreate($attributes, $values), function ($instance) use ($values) {
            if (!$instance->wasRecentlyCreated) {
                $instance->fill($values)->save();
            }
        });
    }
    public function firstWhere($column, $operator = null, $value = null, $boolean = 'and')
    {
        return $this->where($column, $operator, $value, $boolean)->first();
    }
    public function first($columns = ['*'])
    {
        $results = $this->take(1)->get($columns);
        return count($results) > 0 ? $results->first() : null;
    }
    public function firstOrFail($columns = ['*'])
    {
        if (!is_null($model = $this->first($columns))) {
            return $model;
        }
        throw (new ModelNotFoundException())->setModel(get_class($this->related));
    }
    public function firstOr($columns = ['*'], ?Closure $callback = null)
    {
        if ($columns instanceof Closure) {
            $callback = $columns;
            $columns = ['*'];
        }
        if (!is_null($model = $this->first($columns))) {
            return $model;
        }
        return $callback();
    }
    public function find($id, $columns = ['*'])
    {
        if (is_array($id) || $id instanceof Arrayable) {
            return $this->findMany($id, $columns);
        }
        return $this->where($this->getRelated()->getQualifiedKeyName(), '=', $id)->first($columns);
    }
    public function findMany($ids, $columns = ['*'])
    {
        $ids = $ids instanceof Arrayable ? $ids->toArray() : $ids;
        if (empty($ids)) {
            return $this->getRelated()->newCollection();
        }
        return $this->whereIn($this->getRelated()->getQualifiedKeyName(), $ids)->get($columns);
    }
    public function findOrFail($id, $columns = ['*'])
    {
        $result = $this->find($id, $columns);
        $id = $id instanceof Arrayable ? $id->toArray() : $id;
        if (is_array($id)) {
            if (count($result) === count(array_unique($id))) {
                return $result;
            }
        } elseif (!is_null($result)) {
            return $result;
        }
        throw (new ModelNotFoundException())->setModel(get_class($this->related), $id);
    }
    public function findOr($id, $columns = ['*'], ?Closure $callback = null)
    {
        if ($columns instanceof Closure) {
            $callback = $columns;
            $columns = ['*'];
        }
        $result = $this->find($id, $columns);
        $id = $id instanceof Arrayable ? $id->toArray() : $id;
        if (is_array($id)) {
            if (count($result) === count(array_unique($id))) {
                return $result;
            }
        } elseif (!is_null($result)) {
            return $result;
        }
        return $callback();
    }
    public function getResults()
    {
        return !is_null($this->farParent->{$this->localKey}) ? $this->get() : $this->related->newCollection();
    }
    public function get($columns = ['*'])
    {
        $builder = $this->prepareQueryBuilder($columns);
        $models = $builder->getModels();
        if (count($models) > 0) {
            $models = $builder->eagerLoadRelations($models);
        }
        return $this->related->newCollection($models);
    }
    public function paginate($perPage = null, $columns = ['*'], $pageName = 'page', $page = null)
    {
        $this->query->addSelect($this->shouldSelect($columns));
        return $this->query->paginate($perPage, $columns, $pageName, $page);
    }
    public function simplePaginate($perPage = null, $columns = ['*'], $pageName = 'page', $page = null)
    {
        $this->query->addSelect($this->shouldSelect($columns));
        return $this->query->simplePaginate($perPage, $columns, $pageName, $page);
    }
    public function cursorPaginate($perPage = null, $columns = ['*'], $cursorName = 'cursor', $cursor = null)
    {
        $this->query->addSelect($this->shouldSelect($columns));
        return $this->query->cursorPaginate($perPage, $columns, $cursorName, $cursor);
    }
    protected function shouldSelect(array $columns = ['*'])
    {
        if ($columns == ['*']) {
            $columns = [$this->related->getTable() . '.*'];
        }
        return array_merge($columns, [$this->getQualifiedFirstKeyName() . ' as laravel_through_key']);
    }
    public function chunk($count, callable $callback)
    {
        return $this->prepareQueryBuilder()->chunk($count, $callback);
    }
    public function chunkById($count, callable $callback, $column = null, $alias = null)
    {
        $column ??= $this->getRelated()->getQualifiedKeyName();
        $alias ??= $this->getRelated()->getKeyName();
        return $this->prepareQueryBuilder()->chunkById($count, $callback, $column, $alias);
    }
    public function chunkByIdDesc($count, callable $callback, $column = null, $alias = null)
    {
        $column ??= $this->getRelated()->getQualifiedKeyName();
        $alias ??= $this->getRelated()->getKeyName();
        return $this->prepareQueryBuilder()->chunkByIdDesc($count, $callback, $column, $alias);
    }
    public function eachById(callable $callback, $count = 1000, $column = null, $alias = null)
    {
        $column = $column ?? $this->getRelated()->getQualifiedKeyName();
        $alias = $alias ?? $this->getRelated()->getKeyName();
        return $this->prepareQueryBuilder()->eachById($callback, $count, $column, $alias);
    }
    public function cursor()
    {
        return $this->prepareQueryBuilder()->cursor();
    }
    public function each(callable $callback, $count = 1000)
    {
        return $this->chunk($count, function ($results) use ($callback) {
            foreach ($results as $key => $value) {
                if ($callback($value, $key) === false) {
                    return false;
                }
            }
        });
    }
    public function lazy($chunkSize = 1000)
    {
        return $this->prepareQueryBuilder()->lazy($chunkSize);
    }
    public function lazyById($chunkSize = 1000, $column = null, $alias = null)
    {
        $column ??= $this->getRelated()->getQualifiedKeyName();
        $alias ??= $this->getRelated()->getKeyName();
        return $this->prepareQueryBuilder()->lazyById($chunkSize, $column, $alias);
    }
    public function lazyByIdDesc($chunkSize = 1000, $column = null, $alias = null)
    {
        $column ??= $this->getRelated()->getQualifiedKeyName();
        $alias ??= $this->getRelated()->getKeyName();
        return $this->prepareQueryBuilder()->lazyByIdDesc($chunkSize, $column, $alias);
    }
    protected function prepareQueryBuilder($columns = ['*'])
    {
        $builder = $this->query->applyScopes();
        return $builder->addSelect($this->shouldSelect($builder->getQuery()->columns ? [] : $columns));
    }
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        if ($parentQuery->getQuery()->from === $query->getQuery()->from) {
            return $this->getRelationExistenceQueryForSelfRelation($query, $parentQuery, $columns);
        }
        if ($parentQuery->getQuery()->from === $this->throughParent->getTable()) {
            return $this->getRelationExistenceQueryForThroughSelfRelation($query, $parentQuery, $columns);
        }
        $this->performJoin($query);
        return $query->select($columns)->whereColumn($this->getQualifiedLocalKeyName(), '=', $this->getQualifiedFirstKeyName());
    }
    public function getRelationExistenceQueryForSelfRelation(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        $query->from($query->getModel()->getTable() . ' as ' . $hash = $this->getRelationCountHash());
        $query->join($this->throughParent->getTable(), $this->getQualifiedParentKeyName(), '=', $hash . '.' . $this->secondKey);
        if ($this->throughParentSoftDeletes()) {
            $query->whereNull($this->throughParent->getQualifiedDeletedAtColumn());
        }
        $query->getModel()->setTable($hash);
        return $query->select($columns)->whereColumn($parentQuery->getQuery()->from . '.' . $this->localKey, '=', $this->getQualifiedFirstKeyName());
    }
    public function getRelationExistenceQueryForThroughSelfRelation(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        $table = $this->throughParent->getTable() . ' as ' . $hash = $this->getRelationCountHash();
        $query->join($table, $hash . '.' . $this->secondLocalKey, '=', $this->getQualifiedFarKeyName());
        if ($this->throughParentSoftDeletes()) {
            $query->whereNull($hash . '.' . $this->throughParent->getDeletedAtColumn());
        }
        return $query->select($columns)->whereColumn($parentQuery->getQuery()->from . '.' . $this->localKey, '=', $hash . '.' . $this->firstKey);
    }
    public function getQualifiedFarKeyName()
    {
        return $this->getQualifiedForeignKeyName();
    }
    public function getFirstKeyName()
    {
        return $this->firstKey;
    }
    public function getQualifiedFirstKeyName()
    {
        return $this->throughParent->qualifyColumn($this->firstKey);
    }
    public function getForeignKeyName()
    {
        return $this->secondKey;
    }
    public function getQualifiedForeignKeyName()
    {
        return $this->related->qualifyColumn($this->secondKey);
    }
    public function getLocalKeyName()
    {
        return $this->localKey;
    }
    public function getQualifiedLocalKeyName()
    {
        return $this->farParent->qualifyColumn($this->localKey);
    }
    public function getSecondLocalKeyName()
    {
        return $this->secondLocalKey;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Closure;
use Illuminate\Contracts\Database\Eloquent\Builder as BuilderContract;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\MultipleRecordsFoundException;
use Illuminate\Database\Query\Expression;
use Illuminate\Support\Traits\ForwardsCalls;
use Illuminate\Support\Traits\Macroable;
abstract class Relation implements BuilderContract
{
    use ForwardsCalls, Macroable {
        Macroable::__call as macroCall;
    }
    protected $query;
    protected $parent;
    protected $related;
    protected $eagerKeysWereEmpty = false;
    protected static $constraints = true;
    public static $morphMap = [];
    protected static $requireMorphMap = false;
    protected static $selfJoinCount = 0;
    public function __construct(Builder $query, Model $parent)
    {
        $this->query = $query;
        $this->parent = $parent;
        $this->related = $query->getModel();
        $this->addConstraints();
    }
    public static function noConstraints(Closure $callback)
    {
        $previous = static::$constraints;
        static::$constraints = false;
        try {
            return $callback();
        } finally {
            static::$constraints = $previous;
        }
    }
    abstract public function addConstraints();
    abstract public function addEagerConstraints(array $models);
    abstract public function initRelation(array $models, $relation);
    abstract public function match(array $models, Collection $results, $relation);
    abstract public function getResults();
    public function getEager()
    {
        return $this->eagerKeysWereEmpty ? $this->query->getModel()->newCollection() : $this->get();
    }
    public function sole($columns = ['*'])
    {
        $result = $this->take(2)->get($columns);
        $count = $result->count();
        if ($count === 0) {
            throw (new ModelNotFoundException())->setModel(get_class($this->related));
        }
        if ($count > 1) {
            throw new MultipleRecordsFoundException($count);
        }
        return $result->first();
    }
    public function get($columns = ['*'])
    {
        return $this->query->get($columns);
    }
    public function touch()
    {
        $model = $this->getRelated();
        if (!$model::isIgnoringTouch()) {
            $this->rawUpdate([$model->getUpdatedAtColumn() => $model->freshTimestampString()]);
        }
    }
    public function rawUpdate(array $attributes = [])
    {
        return $this->query->withoutGlobalScopes()->update($attributes);
    }
    public function getRelationExistenceCountQuery(Builder $query, Builder $parentQuery)
    {
        return $this->getRelationExistenceQuery($query, $parentQuery, new Expression('count(*)'))->setBindings([], 'select');
    }
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        return $query->select($columns)->whereColumn($this->getQualifiedParentKeyName(), '=', $this->getExistenceCompareKey());
    }
    public function getRelationCountHash($incrementJoinCount = true)
    {
        return 'laravel_reserved_' . ($incrementJoinCount ? static::$selfJoinCount++ : static::$selfJoinCount);
    }
    protected function getKeys(array $models, $key = null)
    {
        return collect($models)->map(function ($value) use ($key) {
            return $key ? $value->getAttribute($key) : $value->getKey();
        })->values()->unique(null, true)->sort()->all();
    }
    protected function getRelationQuery()
    {
        return $this->query;
    }
    public function getQuery()
    {
        return $this->query;
    }
    public function getBaseQuery()
    {
        return $this->query->getQuery();
    }
    public function toBase()
    {
        return $this->query->toBase();
    }
    public function getParent()
    {
        return $this->parent;
    }
    public function getQualifiedParentKeyName()
    {
        return $this->parent->getQualifiedKeyName();
    }
    public function getRelated()
    {
        return $this->related;
    }
    public function createdAt()
    {
        return $this->parent->getCreatedAtColumn();
    }
    public function updatedAt()
    {
        return $this->parent->getUpdatedAtColumn();
    }
    public function relatedUpdatedAt()
    {
        return $this->related->getUpdatedAtColumn();
    }
    protected function whereInEager(string $whereIn, string $key, array $modelKeys, $query = null)
    {
        ($query ?? $this->query)->{$whereIn}($key, $modelKeys);
        if ($modelKeys === []) {
            $this->eagerKeysWereEmpty = true;
        }
    }
    protected function whereInMethod(Model $model, $key)
    {
        return $model->getKeyName() === last(explode('.', $key)) && in_array($model->getKeyType(), ['int', 'integer']) ? 'whereIntegerInRaw' : 'whereIn';
    }
    public static function requireMorphMap($requireMorphMap = true)
    {
        static::$requireMorphMap = $requireMorphMap;
    }
    public static function requiresMorphMap()
    {
        return static::$requireMorphMap;
    }
    public static function enforceMorphMap(array $map, $merge = true)
    {
        static::requireMorphMap();
        return static::morphMap($map, $merge);
    }
    public static function morphMap(?array $map = null, $merge = true)
    {
        $map = static::buildMorphMapFromModels($map);
        if (is_array($map)) {
            static::$morphMap = $merge && static::$morphMap ? $map + static::$morphMap : $map;
        }
        return static::$morphMap;
    }
    protected static function buildMorphMapFromModels(?array $models = null)
    {
        if (is_null($models) || !array_is_list($models)) {
            return $models;
        }
        return array_combine(array_map(function ($model) {
            return (new $model())->getTable();
        }, $models), $models);
    }
    public static function getMorphedModel($alias)
    {
        return static::$morphMap[$alias] ?? null;
    }
    public function __call($method, $parameters)
    {
        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }
        return $this->forwardDecoratedCallTo($this->query, $method, $parameters);
    }
    public function __clone()
    {
        $this->query = clone $this->query;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Concerns\InteractsWithDictionary;
use Illuminate\Database\UniqueConstraintViolationException;
abstract class HasOneOrMany extends Relation
{
    use InteractsWithDictionary;
    protected $foreignKey;
    protected $localKey;
    public function __construct(Builder $query, Model $parent, $foreignKey, $localKey)
    {
        $this->localKey = $localKey;
        $this->foreignKey = $foreignKey;
        parent::__construct($query, $parent);
    }
    public function make(array $attributes = [])
    {
        return tap($this->related->newInstance($attributes), function ($instance) {
            $this->setForeignAttributesForCreate($instance);
        });
    }
    public function makeMany($records)
    {
        $instances = $this->related->newCollection();
        foreach ($records as $record) {
            $instances->push($this->make($record));
        }
        return $instances;
    }
    public function addConstraints()
    {
        if (static::$constraints) {
            $query = $this->getRelationQuery();
            $query->where($this->foreignKey, '=', $this->getParentKey());
            $query->whereNotNull($this->foreignKey);
        }
    }
    public function addEagerConstraints(array $models)
    {
        $whereIn = $this->whereInMethod($this->parent, $this->localKey);
        $this->whereInEager($whereIn, $this->foreignKey, $this->getKeys($models, $this->localKey), $this->getRelationQuery());
    }
    public function matchOne(array $models, Collection $results, $relation)
    {
        return $this->matchOneOrMany($models, $results, $relation, 'one');
    }
    public function matchMany(array $models, Collection $results, $relation)
    {
        return $this->matchOneOrMany($models, $results, $relation, 'many');
    }
    protected function matchOneOrMany(array $models, Collection $results, $relation, $type)
    {
        $dictionary = $this->buildDictionary($results);
        foreach ($models as $model) {
            if (isset($dictionary[$key = $this->getDictionaryKey($model->getAttribute($this->localKey))])) {
                $model->setRelation($relation, $this->getRelationValue($dictionary, $key, $type));
            }
        }
        return $models;
    }
    protected function getRelationValue(array $dictionary, $key, $type)
    {
        $value = $dictionary[$key];
        return $type === 'one' ? reset($value) : $this->related->newCollection($value);
    }
    protected function buildDictionary(Collection $results)
    {
        $foreign = $this->getForeignKeyName();
        return $results->mapToDictionary(function ($result) use ($foreign) {
            return [$this->getDictionaryKey($result->{$foreign}) => $result];
        })->all();
    }
    public function findOrNew($id, $columns = ['*'])
    {
        if (is_null($instance = $this->find($id, $columns))) {
            $instance = $this->related->newInstance();
            $this->setForeignAttributesForCreate($instance);
        }
        return $instance;
    }
    public function firstOrNew(array $attributes = [], array $values = [])
    {
        if (is_null($instance = $this->where($attributes)->first())) {
            $instance = $this->related->newInstance(array_merge($attributes, $values));
            $this->setForeignAttributesForCreate($instance);
        }
        return $instance;
    }
    public function firstOrCreate(array $attributes = [], array $values = [])
    {
        if (is_null($instance = (clone $this)->where($attributes)->first())) {
            $instance = $this->createOrFirst($attributes, $values);
        }
        return $instance;
    }
    public function createOrFirst(array $attributes = [], array $values = [])
    {
        try {
            return $this->getQuery()->withSavepointIfNeeded(fn() => $this->create(array_merge($attributes, $values)));
        } catch (UniqueConstraintViolationException $e) {
            return $this->useWritePdo()->where($attributes)->first() ?? throw $e;
        }
    }
    public function updateOrCreate(array $attributes, array $values = [])
    {
        return tap($this->firstOrCreate($attributes, $values), function ($instance) use ($values) {
            if (!$instance->wasRecentlyCreated) {
                $instance->fill($values)->save();
            }
        });
    }
    public function save(Model $model)
    {
        $this->setForeignAttributesForCreate($model);
        return $model->save() ? $model : false;
    }
    public function saveQuietly(Model $model)
    {
        return Model::withoutEvents(function () use ($model) {
            return $this->save($model);
        });
    }
    public function saveMany($models)
    {
        foreach ($models as $model) {
            $this->save($model);
        }
        return $models;
    }
    public function saveManyQuietly($models)
    {
        return Model::withoutEvents(function () use ($models) {
            return $this->saveMany($models);
        });
    }
    public function create(array $attributes = [])
    {
        return tap($this->related->newInstance($attributes), function ($instance) {
            $this->setForeignAttributesForCreate($instance);
            $instance->save();
        });
    }
    public function createQuietly(array $attributes = [])
    {
        return Model::withoutEvents(fn() => $this->create($attributes));
    }
    public function forceCreate(array $attributes = [])
    {
        $attributes[$this->getForeignKeyName()] = $this->getParentKey();
        return $this->related->forceCreate($attributes);
    }
    public function forceCreateQuietly(array $attributes = [])
    {
        return Model::withoutEvents(fn() => $this->forceCreate($attributes));
    }
    public function createMany(iterable $records)
    {
        $instances = $this->related->newCollection();
        foreach ($records as $record) {
            $instances->push($this->create($record));
        }
        return $instances;
    }
    public function createManyQuietly(iterable $records)
    {
        return Model::withoutEvents(fn() => $this->createMany($records));
    }
    protected function setForeignAttributesForCreate(Model $model)
    {
        $model->setAttribute($this->getForeignKeyName(), $this->getParentKey());
    }
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        if ($query->getQuery()->from == $parentQuery->getQuery()->from) {
            return $this->getRelationExistenceQueryForSelfRelation($query, $parentQuery, $columns);
        }
        return parent::getRelationExistenceQuery($query, $parentQuery, $columns);
    }
    public function getRelationExistenceQueryForSelfRelation(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        $query->from($query->getModel()->getTable() . ' as ' . $hash = $this->getRelationCountHash());
        $query->getModel()->setTable($hash);
        return $query->select($columns)->whereColumn($this->getQualifiedParentKeyName(), '=', $hash . '.' . $this->getForeignKeyName());
    }
    public function getExistenceCompareKey()
    {
        return $this->getQualifiedForeignKeyName();
    }
    public function getParentKey()
    {
        return $this->parent->getAttribute($this->localKey);
    }
    public function getQualifiedParentKeyName()
    {
        return $this->parent->qualifyColumn($this->localKey);
    }
    public function getForeignKeyName()
    {
        $segments = explode('.', $this->getQualifiedForeignKeyName());
        return end($segments);
    }
    public function getQualifiedForeignKeyName()
    {
        return $this->foreignKey;
    }
    public function getLocalKeyName()
    {
        return $this->localKey;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
class MorphMany extends MorphOneOrMany
{
    public function one()
    {
        return MorphOne::noConstraints(fn() => new MorphOne($this->getQuery(), $this->getParent(), $this->morphType, $this->foreignKey, $this->localKey));
    }
    public function getResults()
    {
        return !is_null($this->getParentKey()) ? $this->query->get() : $this->related->newCollection();
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->related->newCollection());
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $this->matchMany($models, $results, $relation);
    }
    public function forceCreate(array $attributes = [])
    {
        $attributes[$this->getMorphType()] = $this->morphClass;
        return parent::forceCreate($attributes);
    }
    public function forceCreateQuietly(array $attributes = [])
    {
        return Model::withoutEvents(fn() => $this->forceCreate($attributes));
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Concerns\AsPivot;
class Pivot extends Model
{
    use AsPivot;
    public $incrementing = false;
    protected $guarded = [];
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Contracts\Database\Eloquent\SupportsPartialRelations;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Concerns\CanBeOneOfMany;
use Illuminate\Database\Eloquent\Relations\Concerns\ComparesRelatedModels;
use Illuminate\Database\Eloquent\Relations\Concerns\SupportsDefaultModels;
use Illuminate\Database\Query\JoinClause;
class MorphOne extends MorphOneOrMany implements SupportsPartialRelations
{
    use CanBeOneOfMany, ComparesRelatedModels, SupportsDefaultModels;
    public function getResults()
    {
        if (is_null($this->getParentKey())) {
            return $this->getDefaultFor($this->parent);
        }
        return $this->query->first() ?: $this->getDefaultFor($this->parent);
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->getDefaultFor($model));
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $this->matchOne($models, $results, $relation);
    }
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        if ($this->isOneOfMany()) {
            $this->mergeOneOfManyJoinsTo($query);
        }
        return parent::getRelationExistenceQuery($query, $parentQuery, $columns);
    }
    public function addOneOfManySubQueryConstraints(Builder $query, $column = null, $aggregate = null)
    {
        $query->addSelect($this->foreignKey, $this->morphType);
    }
    public function getOneOfManySubQuerySelectColumns()
    {
        return [$this->foreignKey, $this->morphType];
    }
    public function addOneOfManyJoinSubQueryConstraints(JoinClause $join)
    {
        $join->on($this->qualifySubSelectColumn($this->morphType), '=', $this->qualifyRelatedColumn($this->morphType))->on($this->qualifySubSelectColumn($this->foreignKey), '=', $this->qualifyRelatedColumn($this->foreignKey));
    }
    public function newRelatedInstanceFor(Model $parent)
    {
        return $this->related->newInstance()->setAttribute($this->getForeignKeyName(), $parent->{$this->localKey})->setAttribute($this->getMorphType(), $this->morphClass);
    }
    protected function getRelatedKeyFrom(Model $model)
    {
        return $model->getAttribute($this->getForeignKeyName());
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Collection;
class HasMany extends HasOneOrMany
{
    public function one()
    {
        return HasOne::noConstraints(fn() => new HasOne($this->getQuery(), $this->parent, $this->foreignKey, $this->localKey));
    }
    public function getResults()
    {
        return !is_null($this->getParentKey()) ? $this->query->get() : $this->related->newCollection();
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->related->newCollection());
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $this->matchMany($models, $results, $relation);
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;
class MorphToMany extends BelongsToMany
{
    protected $morphType;
    protected $morphClass;
    protected $inverse;
    public function __construct(Builder $query, Model $parent, $name, $table, $foreignPivotKey, $relatedPivotKey, $parentKey, $relatedKey, $relationName = null, $inverse = false)
    {
        $this->inverse = $inverse;
        $this->morphType = $name . '_type';
        $this->morphClass = $inverse ? $query->getModel()->getMorphClass() : $parent->getMorphClass();
        parent::__construct($query, $parent, $table, $foreignPivotKey, $relatedPivotKey, $parentKey, $relatedKey, $relationName);
    }
    protected function addWhereConstraints()
    {
        parent::addWhereConstraints();
        $this->query->where($this->qualifyPivotColumn($this->morphType), $this->morphClass);
        return $this;
    }
    public function addEagerConstraints(array $models)
    {
        parent::addEagerConstraints($models);
        $this->query->where($this->qualifyPivotColumn($this->morphType), $this->morphClass);
    }
    protected function baseAttachRecord($id, $timed)
    {
        return Arr::add(parent::baseAttachRecord($id, $timed), $this->morphType, $this->morphClass);
    }
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        return parent::getRelationExistenceQuery($query, $parentQuery, $columns)->where($this->qualifyPivotColumn($this->morphType), $this->morphClass);
    }
    protected function getCurrentlyAttachedPivots()
    {
        return parent::getCurrentlyAttachedPivots()->map(function ($record) {
            return $record instanceof MorphPivot ? $record->setMorphType($this->morphType)->setMorphClass($this->morphClass) : $record;
        });
    }
    public function newPivotQuery()
    {
        return parent::newPivotQuery()->where($this->morphType, $this->morphClass);
    }
    public function newPivot(array $attributes = [], $exists = false)
    {
        $using = $this->using;
        $attributes = array_merge([$this->morphType => $this->morphClass], $attributes);
        $pivot = $using ? $using::fromRawAttributes($this->parent, $attributes, $this->table, $exists) : MorphPivot::fromAttributes($this->parent, $attributes, $this->table, $exists);
        $pivot->setPivotKeys($this->foreignPivotKey, $this->relatedPivotKey)->setMorphType($this->morphType)->setMorphClass($this->morphClass);
        return $pivot;
    }
    protected function aliasedPivotColumns()
    {
        $defaults = [$this->foreignPivotKey, $this->relatedPivotKey, $this->morphType];
        return collect(array_merge($defaults, $this->pivotColumns))->map(function ($column) {
            return $this->qualifyPivotColumn($column) . ' as pivot_' . $column;
        })->unique()->all();
    }
    public function getMorphType()
    {
        return $this->morphType;
    }
    public function getQualifiedMorphTypeName()
    {
        return $this->qualifyPivotColumn($this->morphType);
    }
    public function getMorphClass()
    {
        return $this->morphClass;
    }
    public function getInverse()
    {
        return $this->inverse;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
abstract class MorphOneOrMany extends HasOneOrMany
{
    protected $morphType;
    protected $morphClass;
    public function __construct(Builder $query, Model $parent, $type, $id, $localKey)
    {
        $this->morphType = $type;
        $this->morphClass = $parent->getMorphClass();
        parent::__construct($query, $parent, $id, $localKey);
    }
    public function addConstraints()
    {
        if (static::$constraints) {
            $this->getRelationQuery()->where($this->morphType, $this->morphClass);
            parent::addConstraints();
        }
    }
    public function addEagerConstraints(array $models)
    {
        parent::addEagerConstraints($models);
        $this->getRelationQuery()->where($this->morphType, $this->morphClass);
    }
    public function forceCreate(array $attributes = [])
    {
        $attributes[$this->getForeignKeyName()] = $this->getParentKey();
        $attributes[$this->getMorphType()] = $this->morphClass;
        return $this->related->forceCreate($attributes);
    }
    protected function setForeignAttributesForCreate(Model $model)
    {
        $model->{$this->getForeignKeyName()} = $this->getParentKey();
        $model->{$this->getMorphType()} = $this->morphClass;
    }
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        return parent::getRelationExistenceQuery($query, $parentQuery, $columns)->where($query->qualifyColumn($this->getMorphType()), $this->morphClass);
    }
    public function getQualifiedMorphType()
    {
        return $this->morphType;
    }
    public function getMorphType()
    {
        return last(explode('.', $this->morphType));
    }
    public function getMorphClass()
    {
        return $this->morphClass;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
class MorphPivot extends Pivot
{
    protected $morphType;
    protected $morphClass;
    protected function setKeysForSaveQuery($query)
    {
        $query->where($this->morphType, $this->morphClass);
        return parent::setKeysForSaveQuery($query);
    }
    protected function setKeysForSelectQuery($query)
    {
        $query->where($this->morphType, $this->morphClass);
        return parent::setKeysForSelectQuery($query);
    }
    public function delete()
    {
        if (isset($this->attributes[$this->getKeyName()])) {
            return (int) parent::delete();
        }
        if ($this->fireModelEvent('deleting') === false) {
            return 0;
        }
        $query = $this->getDeleteQuery();
        $query->where($this->morphType, $this->morphClass);
        return tap($query->delete(), function () {
            $this->exists = false;
            $this->fireModelEvent('deleted', false);
        });
    }
    public function getMorphType()
    {
        return $this->morphType;
    }
    public function setMorphType($morphType)
    {
        $this->morphType = $morphType;
        return $this;
    }
    public function setMorphClass($morphClass)
    {
        $this->morphClass = $morphClass;
        return $this;
    }
    public function getQueueableId()
    {
        if (isset($this->attributes[$this->getKeyName()])) {
            return $this->getKey();
        }
        return sprintf('%s:%s:%s:%s:%s:%s', $this->foreignKey, $this->getAttribute($this->foreignKey), $this->relatedKey, $this->getAttribute($this->relatedKey), $this->morphType, $this->morphClass);
    }
    public function newQueryForRestoration($ids)
    {
        if (is_array($ids)) {
            return $this->newQueryForCollectionRestoration($ids);
        }
        if (!str_contains($ids, ':')) {
            return parent::newQueryForRestoration($ids);
        }
        $segments = explode(':', $ids);
        return $this->newQueryWithoutScopes()->where($segments[0], $segments[1])->where($segments[2], $segments[3])->where($segments[4], $segments[5]);
    }
    protected function newQueryForCollectionRestoration(array $ids)
    {
        $ids = array_values($ids);
        if (!str_contains($ids[0], ':')) {
            return parent::newQueryForRestoration($ids);
        }
        $query = $this->newQueryWithoutScopes();
        foreach ($ids as $id) {
            $segments = explode(':', $id);
            $query->orWhere(function ($query) use ($segments) {
                return $query->where($segments[0], $segments[1])->where($segments[2], $segments[3])->where($segments[4], $segments[5]);
            });
        }
        return $query;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Contracts\Database\Eloquent\SupportsPartialRelations;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Concerns\CanBeOneOfMany;
use Illuminate\Database\Eloquent\Relations\Concerns\ComparesRelatedModels;
use Illuminate\Database\Eloquent\Relations\Concerns\SupportsDefaultModels;
use Illuminate\Database\Query\JoinClause;
class HasOne extends HasOneOrMany implements SupportsPartialRelations
{
    use ComparesRelatedModels, CanBeOneOfMany, SupportsDefaultModels;
    public function getResults()
    {
        if (is_null($this->getParentKey())) {
            return $this->getDefaultFor($this->parent);
        }
        return $this->query->first() ?: $this->getDefaultFor($this->parent);
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->getDefaultFor($model));
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $this->matchOne($models, $results, $relation);
    }
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        if ($this->isOneOfMany()) {
            $this->mergeOneOfManyJoinsTo($query);
        }
        return parent::getRelationExistenceQuery($query, $parentQuery, $columns);
    }
    public function addOneOfManySubQueryConstraints(Builder $query, $column = null, $aggregate = null)
    {
        $query->addSelect($this->foreignKey);
    }
    public function getOneOfManySubQuerySelectColumns()
    {
        return $this->foreignKey;
    }
    public function addOneOfManyJoinSubQueryConstraints(JoinClause $join)
    {
        $join->on($this->qualifySubSelectColumn($this->foreignKey), '=', $this->qualifyRelatedColumn($this->foreignKey));
    }
    public function newRelatedInstanceFor(Model $parent)
    {
        return $this->related->newInstance()->setAttribute($this->getForeignKeyName(), $parent->{$this->localKey});
    }
    protected function getRelatedKeyFrom(Model $model)
    {
        return $model->getAttribute($this->getForeignKeyName());
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use BackedEnum;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Concerns\ComparesRelatedModels;
use Illuminate\Database\Eloquent\Relations\Concerns\InteractsWithDictionary;
use Illuminate\Database\Eloquent\Relations\Concerns\SupportsDefaultModels;
class BelongsTo extends Relation
{
    use ComparesRelatedModels, InteractsWithDictionary, SupportsDefaultModels;
    protected $child;
    protected $foreignKey;
    protected $ownerKey;
    protected $relationName;
    public function __construct(Builder $query, Model $child, $foreignKey, $ownerKey, $relationName)
    {
        $this->ownerKey = $ownerKey;
        $this->relationName = $relationName;
        $this->foreignKey = $foreignKey;
        $this->child = $child;
        parent::__construct($query, $child);
    }
    public function getResults()
    {
        if (is_null($this->getForeignKeyFrom($this->child))) {
            return $this->getDefaultFor($this->parent);
        }
        return $this->query->first() ?: $this->getDefaultFor($this->parent);
    }
    public function addConstraints()
    {
        if (static::$constraints) {
            $table = $this->related->getTable();
            $this->query->where($table . '.' . $this->ownerKey, '=', $this->getForeignKeyFrom($this->child));
        }
    }
    public function addEagerConstraints(array $models)
    {
        $key = $this->related->getTable() . '.' . $this->ownerKey;
        $whereIn = $this->whereInMethod($this->related, $this->ownerKey);
        $this->whereInEager($whereIn, $key, $this->getEagerModelKeys($models));
    }
    protected function getEagerModelKeys(array $models)
    {
        $keys = [];
        foreach ($models as $model) {
            if (!is_null($value = $this->getForeignKeyFrom($model))) {
                $keys[] = $value;
            }
        }
        sort($keys);
        return array_values(array_unique($keys));
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->getDefaultFor($model));
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        $dictionary = [];
        foreach ($results as $result) {
            $attribute = $this->getDictionaryKey($this->getRelatedKeyFrom($result));
            $dictionary[$attribute] = $result;
        }
        foreach ($models as $model) {
            $attribute = $this->getDictionaryKey($this->getForeignKeyFrom($model));
            if (isset($dictionary[$attribute])) {
                $model->setRelation($relation, $dictionary[$attribute]);
            }
        }
        return $models;
    }
    public function associate($model)
    {
        $ownerKey = $model instanceof Model ? $model->getAttribute($this->ownerKey) : $model;
        $this->child->setAttribute($this->foreignKey, $ownerKey);
        if ($model instanceof Model) {
            $this->child->setRelation($this->relationName, $model);
        } else {
            $this->child->unsetRelation($this->relationName);
        }
        return $this->child;
    }
    public function dissociate()
    {
        $this->child->setAttribute($this->foreignKey, null);
        return $this->child->setRelation($this->relationName, null);
    }
    public function disassociate()
    {
        return $this->dissociate();
    }
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        if ($parentQuery->getQuery()->from == $query->getQuery()->from) {
            return $this->getRelationExistenceQueryForSelfRelation($query, $parentQuery, $columns);
        }
        return $query->select($columns)->whereColumn($this->getQualifiedForeignKeyName(), '=', $query->qualifyColumn($this->ownerKey));
    }
    public function getRelationExistenceQueryForSelfRelation(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        $query->select($columns)->from($query->getModel()->getTable() . ' as ' . $hash = $this->getRelationCountHash());
        $query->getModel()->setTable($hash);
        return $query->whereColumn($hash . '.' . $this->ownerKey, '=', $this->getQualifiedForeignKeyName());
    }
    protected function relationHasIncrementingId()
    {
        return $this->related->getIncrementing() && in_array($this->related->getKeyType(), ['int', 'integer']);
    }
    protected function newRelatedInstanceFor(Model $parent)
    {
        return $this->related->newInstance();
    }
    public function getChild()
    {
        return $this->child;
    }
    public function getForeignKeyName()
    {
        return $this->foreignKey;
    }
    public function getQualifiedForeignKeyName()
    {
        return $this->child->qualifyColumn($this->foreignKey);
    }
    public function getParentKey()
    {
        return $this->getForeignKeyFrom($this->child);
    }
    public function getOwnerKeyName()
    {
        return $this->ownerKey;
    }
    public function getQualifiedOwnerKeyName()
    {
        return $this->related->qualifyColumn($this->ownerKey);
    }
    protected function getRelatedKeyFrom(Model $model)
    {
        return $model->{$this->ownerKey};
    }
    protected function getForeignKeyFrom(Model $model)
    {
        $foreignKey = $model->{$this->foreignKey};
        return $foreignKey instanceof BackedEnum ? $foreignKey->value : $foreignKey;
    }
    public function getRelationName()
    {
        return $this->relationName;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Closure;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\Eloquent\Relations\Concerns\AsPivot;
use Illuminate\Database\Eloquent\Relations\Concerns\InteractsWithDictionary;
use Illuminate\Database\Eloquent\Relations\Concerns\InteractsWithPivotTable;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Str;
use InvalidArgumentException;
class BelongsToMany extends Relation
{
    use InteractsWithDictionary, InteractsWithPivotTable;
    protected $table;
    protected $foreignPivotKey;
    protected $relatedPivotKey;
    protected $parentKey;
    protected $relatedKey;
    protected $relationName;
    protected $pivotColumns = [];
    protected $pivotWheres = [];
    protected $pivotWhereIns = [];
    protected $pivotWhereNulls = [];
    protected $pivotValues = [];
    public $withTimestamps = false;
    protected $pivotCreatedAt;
    protected $pivotUpdatedAt;
    protected $using;
    protected $accessor = 'pivot';
    public function __construct(Builder $query, Model $parent, $table, $foreignPivotKey, $relatedPivotKey, $parentKey, $relatedKey, $relationName = null)
    {
        $this->parentKey = $parentKey;
        $this->relatedKey = $relatedKey;
        $this->relationName = $relationName;
        $this->relatedPivotKey = $relatedPivotKey;
        $this->foreignPivotKey = $foreignPivotKey;
        $this->table = $this->resolveTableName($table);
        parent::__construct($query, $parent);
    }
    protected function resolveTableName($table)
    {
        if (!str_contains($table, '\\') || !class_exists($table)) {
            return $table;
        }
        $model = new $table();
        if (!$model instanceof Model) {
            return $table;
        }
        if (in_array(AsPivot::class, class_uses_recursive($model))) {
            $this->using($table);
        }
        return $model->getTable();
    }
    public function addConstraints()
    {
        $this->performJoin();
        if (static::$constraints) {
            $this->addWhereConstraints();
        }
    }
    protected function performJoin($query = null)
    {
        $query = $query ?: $this->query;
        $query->join($this->table, $this->getQualifiedRelatedKeyName(), '=', $this->getQualifiedRelatedPivotKeyName());
        return $this;
    }
    protected function addWhereConstraints()
    {
        $this->query->where($this->getQualifiedForeignPivotKeyName(), '=', $this->parent->{$this->parentKey});
        return $this;
    }
    public function addEagerConstraints(array $models)
    {
        $whereIn = $this->whereInMethod($this->parent, $this->parentKey);
        $this->whereInEager($whereIn, $this->getQualifiedForeignPivotKeyName(), $this->getKeys($models, $this->parentKey));
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->related->newCollection());
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        $dictionary = $this->buildDictionary($results);
        foreach ($models as $model) {
            $key = $this->getDictionaryKey($model->{$this->parentKey});
            if (isset($dictionary[$key])) {
                $model->setRelation($relation, $this->related->newCollection($dictionary[$key]));
            }
        }
        return $models;
    }
    protected function buildDictionary(Collection $results)
    {
        $dictionary = [];
        foreach ($results as $result) {
            $value = $this->getDictionaryKey($result->{$this->accessor}->{$this->foreignPivotKey});
            $dictionary[$value][] = $result;
        }
        return $dictionary;
    }
    public function getPivotClass()
    {
        return $this->using ?? Pivot::class;
    }
    public function using($class)
    {
        $this->using = $class;
        return $this;
    }
    public function as($accessor)
    {
        $this->accessor = $accessor;
        return $this;
    }
    public function wherePivot($column, $operator = null, $value = null, $boolean = 'and')
    {
        $this->pivotWheres[] = func_get_args();
        return $this->where($this->qualifyPivotColumn($column), $operator, $value, $boolean);
    }
    public function wherePivotBetween($column, array $values, $boolean = 'and', $not = false)
    {
        return $this->whereBetween($this->qualifyPivotColumn($column), $values, $boolean, $not);
    }
    public function orWherePivotBetween($column, array $values)
    {
        return $this->wherePivotBetween($column, $values, 'or');
    }
    public function wherePivotNotBetween($column, array $values, $boolean = 'and')
    {
        return $this->wherePivotBetween($column, $values, $boolean, true);
    }
    public function orWherePivotNotBetween($column, array $values)
    {
        return $this->wherePivotBetween($column, $values, 'or', true);
    }
    public function wherePivotIn($column, $values, $boolean = 'and', $not = false)
    {
        $this->pivotWhereIns[] = func_get_args();
        return $this->whereIn($this->qualifyPivotColumn($column), $values, $boolean, $not);
    }
    public function orWherePivot($column, $operator = null, $value = null)
    {
        return $this->wherePivot($column, $operator, $value, 'or');
    }
    public function withPivotValue($column, $value = null)
    {
        if (is_array($column)) {
            foreach ($column as $name => $value) {
                $this->withPivotValue($name, $value);
            }
            return $this;
        }
        if (is_null($value)) {
            throw new InvalidArgumentException('The provided value may not be null.');
        }
        $this->pivotValues[] = compact('column', 'value');
        return $this->wherePivot($column, '=', $value);
    }
    public function orWherePivotIn($column, $values)
    {
        return $this->wherePivotIn($column, $values, 'or');
    }
    public function wherePivotNotIn($column, $values, $boolean = 'and')
    {
        return $this->wherePivotIn($column, $values, $boolean, true);
    }
    public function orWherePivotNotIn($column, $values)
    {
        return $this->wherePivotNotIn($column, $values, 'or');
    }
    public function wherePivotNull($column, $boolean = 'and', $not = false)
    {
        $this->pivotWhereNulls[] = func_get_args();
        return $this->whereNull($this->qualifyPivotColumn($column), $boolean, $not);
    }
    public function wherePivotNotNull($column, $boolean = 'and')
    {
        return $this->wherePivotNull($column, $boolean, true);
    }
    public function orWherePivotNull($column, $not = false)
    {
        return $this->wherePivotNull($column, 'or', $not);
    }
    public function orWherePivotNotNull($column)
    {
        return $this->orWherePivotNull($column, true);
    }
    public function orderByPivot($column, $direction = 'asc')
    {
        return $this->orderBy($this->qualifyPivotColumn($column), $direction);
    }
    public function findOrNew($id, $columns = ['*'])
    {
        if (is_null($instance = $this->find($id, $columns))) {
            $instance = $this->related->newInstance();
        }
        return $instance;
    }
    public function firstOrNew(array $attributes = [], array $values = [])
    {
        if (is_null($instance = $this->related->where($attributes)->first())) {
            $instance = $this->related->newInstance(array_merge($attributes, $values));
        }
        return $instance;
    }
    public function firstOrCreate(array $attributes = [], array $values = [], array $joining = [], $touch = true)
    {
        if (is_null($instance = (clone $this)->where($attributes)->first())) {
            if (is_null($instance = $this->related->where($attributes)->first())) {
                $instance = $this->createOrFirst($attributes, $values, $joining, $touch);
            } else {
                try {
                    $this->getQuery()->withSavepointIfNeeded(fn() => $this->attach($instance, $joining, $touch));
                } catch (UniqueConstraintViolationException) {
                }
            }
        }
        return $instance;
    }
    public function createOrFirst(array $attributes = [], array $values = [], array $joining = [], $touch = true)
    {
        try {
            return $this->getQuery()->withSavePointIfNeeded(fn() => $this->create(array_merge($attributes, $values), $joining, $touch));
        } catch (UniqueConstraintViolationException $e) {
        }
        try {
            return tap($this->related->where($attributes)->first() ?? throw $e, function ($instance) use ($joining, $touch) {
                $this->getQuery()->withSavepointIfNeeded(fn() => $this->attach($instance, $joining, $touch));
            });
        } catch (UniqueConstraintViolationException $e) {
            return (clone $this)->useWritePdo()->where($attributes)->first() ?? throw $e;
        }
    }
    public function updateOrCreate(array $attributes, array $values = [], array $joining = [], $touch = true)
    {
        return tap($this->firstOrCreate($attributes, $values, $joining, $touch), function ($instance) use ($values) {
            if (!$instance->wasRecentlyCreated) {
                $instance->fill($values);
                $instance->save(['touch' => false]);
            }
        });
    }
    public function find($id, $columns = ['*'])
    {
        if (!$id instanceof Model && (is_array($id) || $id instanceof Arrayable)) {
            return $this->findMany($id, $columns);
        }
        return $this->where($this->getRelated()->getQualifiedKeyName(), '=', $this->parseId($id))->first($columns);
    }
    public function findMany($ids, $columns = ['*'])
    {
        $ids = $ids instanceof Arrayable ? $ids->toArray() : $ids;
        if (empty($ids)) {
            return $this->getRelated()->newCollection();
        }
        return $this->whereKey($this->parseIds($ids))->get($columns);
    }
    public function findOrFail($id, $columns = ['*'])
    {
        $result = $this->find($id, $columns);
        $id = $id instanceof Arrayable ? $id->toArray() : $id;
        if (is_array($id)) {
            if (count($result) === count(array_unique($id))) {
                return $result;
            }
        } elseif (!is_null($result)) {
            return $result;
        }
        throw (new ModelNotFoundException())->setModel(get_class($this->related), $id);
    }
    public function findOr($id, $columns = ['*'], ?Closure $callback = null)
    {
        if ($columns instanceof Closure) {
            $callback = $columns;
            $columns = ['*'];
        }
        $result = $this->find($id, $columns);
        $id = $id instanceof Arrayable ? $id->toArray() : $id;
        if (is_array($id)) {
            if (count($result) === count(array_unique($id))) {
                return $result;
            }
        } elseif (!is_null($result)) {
            return $result;
        }
        return $callback();
    }
    public function firstWhere($column, $operator = null, $value = null, $boolean = 'and')
    {
        return $this->where($column, $operator, $value, $boolean)->first();
    }
    public function first($columns = ['*'])
    {
        $results = $this->take(1)->get($columns);
        return count($results) > 0 ? $results->first() : null;
    }
    public function firstOrFail($columns = ['*'])
    {
        if (!is_null($model = $this->first($columns))) {
            return $model;
        }
        throw (new ModelNotFoundException())->setModel(get_class($this->related));
    }
    public function firstOr($columns = ['*'], ?Closure $callback = null)
    {
        if ($columns instanceof Closure) {
            $callback = $columns;
            $columns = ['*'];
        }
        if (!is_null($model = $this->first($columns))) {
            return $model;
        }
        return $callback();
    }
    public function getResults()
    {
        return !is_null($this->parent->{$this->parentKey}) ? $this->get() : $this->related->newCollection();
    }
    public function get($columns = ['*'])
    {
        $builder = $this->query->applyScopes();
        $columns = $builder->getQuery()->columns ? [] : $columns;
        $models = $builder->addSelect($this->shouldSelect($columns))->getModels();
        $this->hydratePivotRelation($models);
        if (count($models) > 0) {
            $models = $builder->eagerLoadRelations($models);
        }
        return $this->related->newCollection($models);
    }
    protected function shouldSelect(array $columns = ['*'])
    {
        if ($columns == ['*']) {
            $columns = [$this->related->getTable() . '.*'];
        }
        return array_merge($columns, $this->aliasedPivotColumns());
    }
    protected function aliasedPivotColumns()
    {
        $defaults = [$this->foreignPivotKey, $this->relatedPivotKey];
        return collect(array_merge($defaults, $this->pivotColumns))->map(function ($column) {
            return $this->qualifyPivotColumn($column) . ' as pivot_' . $column;
        })->unique()->all();
    }
    public function paginate($perPage = null, $columns = ['*'], $pageName = 'page', $page = null)
    {
        $this->query->addSelect($this->shouldSelect($columns));
        return tap($this->query->paginate($perPage, $columns, $pageName, $page), function ($paginator) {
            $this->hydratePivotRelation($paginator->items());
        });
    }
    public function simplePaginate($perPage = null, $columns = ['*'], $pageName = 'page', $page = null)
    {
        $this->query->addSelect($this->shouldSelect($columns));
        return tap($this->query->simplePaginate($perPage, $columns, $pageName, $page), function ($paginator) {
            $this->hydratePivotRelation($paginator->items());
        });
    }
    public function cursorPaginate($perPage = null, $columns = ['*'], $cursorName = 'cursor', $cursor = null)
    {
        $this->query->addSelect($this->shouldSelect($columns));
        return tap($this->query->cursorPaginate($perPage, $columns, $cursorName, $cursor), function ($paginator) {
            $this->hydratePivotRelation($paginator->items());
        });
    }
    public function chunk($count, callable $callback)
    {
        return $this->prepareQueryBuilder()->chunk($count, function ($results, $page) use ($callback) {
            $this->hydratePivotRelation($results->all());
            return $callback($results, $page);
        });
    }
    public function chunkById($count, callable $callback, $column = null, $alias = null)
    {
        return $this->orderedChunkById($count, $callback, $column, $alias);
    }
    public function chunkByIdDesc($count, callable $callback, $column = null, $alias = null)
    {
        return $this->orderedChunkById($count, $callback, $column, $alias, descending: true);
    }
    public function eachById(callable $callback, $count = 1000, $column = null, $alias = null)
    {
        return $this->chunkById($count, function ($results, $page) use ($callback, $count) {
            foreach ($results as $key => $value) {
                if ($callback($value, ($page - 1) * $count + $key) === false) {
                    return false;
                }
            }
        }, $column, $alias);
    }
    public function orderedChunkById($count, callable $callback, $column = null, $alias = null, $descending = false)
    {
        $column ??= $this->getRelated()->qualifyColumn($this->getRelatedKeyName());
        $alias ??= $this->getRelatedKeyName();
        return $this->prepareQueryBuilder()->orderedChunkById($count, function ($results, $page) use ($callback) {
            $this->hydratePivotRelation($results->all());
            return $callback($results, $page);
        }, $column, $alias, $descending);
    }
    public function each(callable $callback, $count = 1000)
    {
        return $this->chunk($count, function ($results) use ($callback) {
            foreach ($results as $key => $value) {
                if ($callback($value, $key) === false) {
                    return false;
                }
            }
        });
    }
    public function lazy($chunkSize = 1000)
    {
        return $this->prepareQueryBuilder()->lazy($chunkSize)->map(function ($model) {
            $this->hydratePivotRelation([$model]);
            return $model;
        });
    }
    public function lazyById($chunkSize = 1000, $column = null, $alias = null)
    {
        $column ??= $this->getRelated()->qualifyColumn($this->getRelatedKeyName());
        $alias ??= $this->getRelatedKeyName();
        return $this->prepareQueryBuilder()->lazyById($chunkSize, $column, $alias)->map(function ($model) {
            $this->hydratePivotRelation([$model]);
            return $model;
        });
    }
    public function lazyByIdDesc($chunkSize = 1000, $column = null, $alias = null)
    {
        $column ??= $this->getRelated()->qualifyColumn($this->getRelatedKeyName());
        $alias ??= $this->getRelatedKeyName();
        return $this->prepareQueryBuilder()->lazyByIdDesc($chunkSize, $column, $alias)->map(function ($model) {
            $this->hydratePivotRelation([$model]);
            return $model;
        });
    }
    public function cursor()
    {
        return $this->prepareQueryBuilder()->cursor()->map(function ($model) {
            $this->hydratePivotRelation([$model]);
            return $model;
        });
    }
    protected function prepareQueryBuilder()
    {
        return $this->query->addSelect($this->shouldSelect());
    }
    protected function hydratePivotRelation(array $models)
    {
        foreach ($models as $model) {
            $model->setRelation($this->accessor, $this->newExistingPivot($this->migratePivotAttributes($model)));
        }
    }
    protected function migratePivotAttributes(Model $model)
    {
        $values = [];
        foreach ($model->getAttributes() as $key => $value) {
            if (str_starts_with($key, 'pivot_')) {
                $values[substr($key, 6)] = $value;
                unset($model->{$key});
            }
        }
        return $values;
    }
    public function touchIfTouching()
    {
        if ($this->touchingParent()) {
            $this->getParent()->touch();
        }
        if ($this->getParent()->touches($this->relationName)) {
            $this->touch();
        }
    }
    protected function touchingParent()
    {
        return $this->getRelated()->touches($this->guessInverseRelation());
    }
    protected function guessInverseRelation()
    {
        return Str::camel(Str::pluralStudly(class_basename($this->getParent())));
    }
    public function touch()
    {
        if ($this->related->isIgnoringTouch()) {
            return;
        }
        $columns = [$this->related->getUpdatedAtColumn() => $this->related->freshTimestampString()];
        if (count($ids = $this->allRelatedIds()) > 0) {
            $this->getRelated()->newQueryWithoutRelationships()->whereKey($ids)->update($columns);
        }
    }
    public function allRelatedIds()
    {
        return $this->newPivotQuery()->pluck($this->relatedPivotKey);
    }
    public function save(Model $model, array $pivotAttributes = [], $touch = true)
    {
        $model->save(['touch' => false]);
        $this->attach($model, $pivotAttributes, $touch);
        return $model;
    }
    public function saveQuietly(Model $model, array $pivotAttributes = [], $touch = true)
    {
        return Model::withoutEvents(function () use ($model, $pivotAttributes, $touch) {
            return $this->save($model, $pivotAttributes, $touch);
        });
    }
    public function saveMany($models, array $pivotAttributes = [])
    {
        foreach ($models as $key => $model) {
            $this->save($model, (array) ($pivotAttributes[$key] ?? []), false);
        }
        $this->touchIfTouching();
        return $models;
    }
    public function saveManyQuietly($models, array $pivotAttributes = [])
    {
        return Model::withoutEvents(function () use ($models, $pivotAttributes) {
            return $this->saveMany($models, $pivotAttributes);
        });
    }
    public function create(array $attributes = [], array $joining = [], $touch = true)
    {
        $instance = $this->related->newInstance($attributes);
        $instance->save(['touch' => false]);
        $this->attach($instance, $joining, $touch);
        return $instance;
    }
    public function createMany(iterable $records, array $joinings = [])
    {
        $instances = [];
        foreach ($records as $key => $record) {
            $instances[] = $this->create($record, (array) ($joinings[$key] ?? []), false);
        }
        $this->touchIfTouching();
        return $instances;
    }
    public function getRelationExistenceQuery(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        if ($parentQuery->getQuery()->from == $query->getQuery()->from) {
            return $this->getRelationExistenceQueryForSelfJoin($query, $parentQuery, $columns);
        }
        $this->performJoin($query);
        return parent::getRelationExistenceQuery($query, $parentQuery, $columns);
    }
    public function getRelationExistenceQueryForSelfJoin(Builder $query, Builder $parentQuery, $columns = ['*'])
    {
        $query->select($columns);
        $query->from($this->related->getTable() . ' as ' . $hash = $this->getRelationCountHash());
        $this->related->setTable($hash);
        $this->performJoin($query);
        return parent::getRelationExistenceQuery($query, $parentQuery, $columns);
    }
    public function getExistenceCompareKey()
    {
        return $this->getQualifiedForeignPivotKeyName();
    }
    public function withTimestamps($createdAt = null, $updatedAt = null)
    {
        $this->withTimestamps = true;
        $this->pivotCreatedAt = $createdAt;
        $this->pivotUpdatedAt = $updatedAt;
        return $this->withPivot($this->createdAt(), $this->updatedAt());
    }
    public function createdAt()
    {
        return $this->pivotCreatedAt ?: $this->parent->getCreatedAtColumn();
    }
    public function updatedAt()
    {
        return $this->pivotUpdatedAt ?: $this->parent->getUpdatedAtColumn();
    }
    public function getForeignPivotKeyName()
    {
        return $this->foreignPivotKey;
    }
    public function getQualifiedForeignPivotKeyName()
    {
        return $this->qualifyPivotColumn($this->foreignPivotKey);
    }
    public function getRelatedPivotKeyName()
    {
        return $this->relatedPivotKey;
    }
    public function getQualifiedRelatedPivotKeyName()
    {
        return $this->qualifyPivotColumn($this->relatedPivotKey);
    }
    public function getParentKeyName()
    {
        return $this->parentKey;
    }
    public function getQualifiedParentKeyName()
    {
        return $this->parent->qualifyColumn($this->parentKey);
    }
    public function getRelatedKeyName()
    {
        return $this->relatedKey;
    }
    public function getQualifiedRelatedKeyName()
    {
        return $this->related->qualifyColumn($this->relatedKey);
    }
    public function getTable()
    {
        return $this->table;
    }
    public function getRelationName()
    {
        return $this->relationName;
    }
    public function getPivotAccessor()
    {
        return $this->accessor;
    }
    public function getPivotColumns()
    {
        return $this->pivotColumns;
    }
    public function qualifyPivotColumn($column)
    {
        return str_contains($column, '.') ? $column : $this->table . '.' . $column;
    }
}
}

namespace Illuminate\Database\Eloquent {
class SoftDeletingScope implements Scope
{
    protected $extensions = ['Restore', 'RestoreOrCreate', 'CreateOrRestore', 'WithTrashed', 'WithoutTrashed', 'OnlyTrashed'];
    public function apply(Builder $builder, Model $model)
    {
        $builder->whereNull($model->getQualifiedDeletedAtColumn());
    }
    public function extend(Builder $builder)
    {
        foreach ($this->extensions as $extension) {
            $this->{"add{$extension}"}($builder);
        }
        $builder->onDelete(function (Builder $builder) {
            $column = $this->getDeletedAtColumn($builder);
            return $builder->update([$column => $builder->getModel()->freshTimestampString()]);
        });
    }
    protected function getDeletedAtColumn(Builder $builder)
    {
        if (count((array) $builder->getQuery()->joins) > 0) {
            return $builder->getModel()->getQualifiedDeletedAtColumn();
        }
        return $builder->getModel()->getDeletedAtColumn();
    }
    protected function addRestore(Builder $builder)
    {
        $builder->macro('restore', function (Builder $builder) {
            $builder->withTrashed();
            return $builder->update([$builder->getModel()->getDeletedAtColumn() => null]);
        });
    }
    protected function addRestoreOrCreate(Builder $builder)
    {
        $builder->macro('restoreOrCreate', function (Builder $builder, array $attributes = [], array $values = []) {
            $builder->withTrashed();
            return tap($builder->firstOrCreate($attributes, $values), function ($instance) {
                $instance->restore();
            });
        });
    }
    protected function addCreateOrRestore(Builder $builder)
    {
        $builder->macro('createOrRestore', function (Builder $builder, array $attributes = [], array $values = []) {
            $builder->withTrashed();
            return tap($builder->createOrFirst($attributes, $values), function ($instance) {
                $instance->restore();
            });
        });
    }
    protected function addWithTrashed(Builder $builder)
    {
        $builder->macro('withTrashed', function (Builder $builder, $withTrashed = true) {
            if (!$withTrashed) {
                return $builder->withoutTrashed();
            }
            return $builder->withoutGlobalScope($this);
        });
    }
    protected function addWithoutTrashed(Builder $builder)
    {
        $builder->macro('withoutTrashed', function (Builder $builder) {
            $model = $builder->getModel();
            $builder->withoutGlobalScope($this)->whereNull($model->getQualifiedDeletedAtColumn());
            return $builder;
        });
    }
    protected function addOnlyTrashed(Builder $builder)
    {
        $builder->macro('onlyTrashed', function (Builder $builder) {
            $model = $builder->getModel();
            $builder->withoutGlobalScope($this)->whereNotNull($model->getQualifiedDeletedAtColumn());
            return $builder;
        });
    }
}
}

namespace Illuminate\Database\Eloquent {
use Illuminate\Database\RecordsNotFoundException;
use Illuminate\Support\Arr;
class ModelNotFoundException extends RecordsNotFoundException
{
    protected $model;
    protected $ids;
    public function setModel($model, $ids = [])
    {
        $this->model = $model;
        $this->ids = Arr::wrap($ids);
        $this->message = "No query results for model [{$model}]";
        if (count($this->ids) > 0) {
            $this->message .= ' ' . implode(', ', $this->ids);
        } else {
            $this->message .= '.';
        }
        return $this;
    }
    public function getModel()
    {
        return $this->model;
    }
    public function getIds()
    {
        return $this->ids;
    }
}
}

namespace Illuminate\Database\Eloquent {
use Illuminate\Contracts\Queue\EntityNotFoundException;
use Illuminate\Contracts\Queue\EntityResolver as EntityResolverContract;
class QueueEntityResolver implements EntityResolverContract
{
    public function resolve($type, $id)
    {
        $instance = (new $type())->find($id);
        if ($instance) {
            return $instance;
        }
        throw new EntityNotFoundException($type, $id);
    }
}
}

namespace Illuminate\Database\Eloquent {
trait SoftDeletes
{
    protected $forceDeleting = false;
    public static function bootSoftDeletes()
    {
        static::addGlobalScope(new SoftDeletingScope());
    }
    public function initializeSoftDeletes()
    {
        if (!isset($this->casts[$this->getDeletedAtColumn()])) {
            $this->casts[$this->getDeletedAtColumn()] = 'datetime';
        }
    }
    public function forceDelete()
    {
        if ($this->fireModelEvent('forceDeleting') === false) {
            return false;
        }
        $this->forceDeleting = true;
        return tap($this->delete(), function ($deleted) {
            $this->forceDeleting = false;
            if ($deleted) {
                $this->fireModelEvent('forceDeleted', false);
            }
        });
    }
    public function forceDeleteQuietly()
    {
        return static::withoutEvents(fn() => $this->forceDelete());
    }
    protected function performDeleteOnModel()
    {
        if ($this->forceDeleting) {
            return tap($this->setKeysForSaveQuery($this->newModelQuery())->forceDelete(), function () {
                $this->exists = false;
            });
        }
        return $this->runSoftDelete();
    }
    protected function runSoftDelete()
    {
        $query = $this->setKeysForSaveQuery($this->newModelQuery());
        $time = $this->freshTimestamp();
        $columns = [$this->getDeletedAtColumn() => $this->fromDateTime($time)];
        $this->{$this->getDeletedAtColumn()} = $time;
        if ($this->usesTimestamps() && !is_null($this->getUpdatedAtColumn())) {
            $this->{$this->getUpdatedAtColumn()} = $time;
            $columns[$this->getUpdatedAtColumn()] = $this->fromDateTime($time);
        }
        $query->update($columns);
        $this->syncOriginalAttributes(array_keys($columns));
        $this->fireModelEvent('trashed', false);
    }
    public function restore()
    {
        if ($this->fireModelEvent('restoring') === false) {
            return false;
        }
        $this->{$this->getDeletedAtColumn()} = null;
        $this->exists = true;
        $result = $this->save();
        $this->fireModelEvent('restored', false);
        return $result;
    }
    public function restoreQuietly()
    {
        return static::withoutEvents(fn() => $this->restore());
    }
    public function trashed()
    {
        return !is_null($this->{$this->getDeletedAtColumn()});
    }
    public static function softDeleted($callback)
    {
        static::registerModelEvent('trashed', $callback);
    }
    public static function restoring($callback)
    {
        static::registerModelEvent('restoring', $callback);
    }
    public static function restored($callback)
    {
        static::registerModelEvent('restored', $callback);
    }
    public static function forceDeleting($callback)
    {
        static::registerModelEvent('forceDeleting', $callback);
    }
    public static function forceDeleted($callback)
    {
        static::registerModelEvent('forceDeleted', $callback);
    }
    public function isForceDeleting()
    {
        return $this->forceDeleting;
    }
    public function getDeletedAtColumn()
    {
        return defined(static::class . '::DELETED_AT') ? static::DELETED_AT : 'deleted_at';
    }
    public function getQualifiedDeletedAtColumn()
    {
        return $this->qualifyColumn($this->getDeletedAtColumn());
    }
}
}

namespace Illuminate\Database\Eloquent {
use RuntimeException;
class MassAssignmentException extends RuntimeException
{
}
}

namespace Illuminate\Database\Eloquent {
interface Scope
{
    public function apply(Builder $builder, Model $model);
}
}

namespace Illuminate\Database\Eloquent {
use Illuminate\Contracts\Queue\QueueableCollection;
use Illuminate\Contracts\Queue\QueueableEntity;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Database\Eloquent\Relations\Concerns\InteractsWithDictionary;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection as BaseCollection;
use LogicException;
class Collection extends BaseCollection implements QueueableCollection
{
    use InteractsWithDictionary;
    public function find($key, $default = null)
    {
        if ($key instanceof Model) {
            $key = $key->getKey();
        }
        if ($key instanceof Arrayable) {
            $key = $key->toArray();
        }
        if (is_array($key)) {
            if ($this->isEmpty()) {
                return new static();
            }
            return $this->whereIn($this->first()->getKeyName(), $key);
        }
        return Arr::first($this->items, fn($model) => $model->getKey() == $key, $default);
    }
    public function load($relations)
    {
        if ($this->isNotEmpty()) {
            if (is_string($relations)) {
                $relations = func_get_args();
            }
            $query = $this->first()->newQueryWithoutRelationships()->with($relations);
            $this->items = $query->eagerLoadRelations($this->items);
        }
        return $this;
    }
    public function loadAggregate($relations, $column, $function = null)
    {
        if ($this->isEmpty()) {
            return $this;
        }
        $models = $this->first()->newModelQuery()->whereKey($this->modelKeys())->select($this->first()->getKeyName())->withAggregate($relations, $column, $function)->get()->keyBy($this->first()->getKeyName());
        $attributes = Arr::except(array_keys($models->first()->getAttributes()), $models->first()->getKeyName());
        $this->each(function ($model) use ($models, $attributes) {
            $extraAttributes = Arr::only($models->get($model->getKey())->getAttributes(), $attributes);
            $model->forceFill($extraAttributes)->syncOriginalAttributes($attributes)->mergeCasts($models->get($model->getKey())->getCasts());
        });
        return $this;
    }
    public function loadCount($relations)
    {
        return $this->loadAggregate($relations, '*', 'count');
    }
    public function loadMax($relations, $column)
    {
        return $this->loadAggregate($relations, $column, 'max');
    }
    public function loadMin($relations, $column)
    {
        return $this->loadAggregate($relations, $column, 'min');
    }
    public function loadSum($relations, $column)
    {
        return $this->loadAggregate($relations, $column, 'sum');
    }
    public function loadAvg($relations, $column)
    {
        return $this->loadAggregate($relations, $column, 'avg');
    }
    public function loadExists($relations)
    {
        return $this->loadAggregate($relations, '*', 'exists');
    }
    public function loadMissing($relations)
    {
        if (is_string($relations)) {
            $relations = func_get_args();
        }
        foreach ($relations as $key => $value) {
            if (is_numeric($key)) {
                $key = $value;
            }
            $segments = explode('.', explode(':', $key)[0]);
            if (str_contains($key, ':')) {
                $segments[count($segments) - 1] .= ':' . explode(':', $key)[1];
            }
            $path = [];
            foreach ($segments as $segment) {
                $path[] = [$segment => $segment];
            }
            if (is_callable($value)) {
                $path[count($segments) - 1][end($segments)] = $value;
            }
            $this->loadMissingRelation($this, $path);
        }
        return $this;
    }
    protected function loadMissingRelation(self $models, array $path)
    {
        $relation = array_shift($path);
        $name = explode(':', key($relation))[0];
        if (is_string(reset($relation))) {
            $relation = reset($relation);
        }
        $models->filter(fn($model) => !is_null($model) && !$model->relationLoaded($name))->load($relation);
        if (empty($path)) {
            return;
        }
        $models = $models->pluck($name)->whereNotNull();
        if ($models->first() instanceof BaseCollection) {
            $models = $models->collapse();
        }
        $this->loadMissingRelation(new static($models), $path);
    }
    public function loadMorph($relation, $relations)
    {
        $this->pluck($relation)->filter()->groupBy(fn($model) => get_class($model))->each(fn($models, $className) => static::make($models)->load($relations[$className] ?? []));
        return $this;
    }
    public function loadMorphCount($relation, $relations)
    {
        $this->pluck($relation)->filter()->groupBy(fn($model) => get_class($model))->each(fn($models, $className) => static::make($models)->loadCount($relations[$className] ?? []));
        return $this;
    }
    public function contains($key, $operator = null, $value = null)
    {
        if (func_num_args() > 1 || $this->useAsCallable($key)) {
            return parent::contains(...func_get_args());
        }
        if ($key instanceof Model) {
            return parent::contains(fn($model) => $model->is($key));
        }
        return parent::contains(fn($model) => $model->getKey() == $key);
    }
    public function modelKeys()
    {
        return array_map(fn($model) => $model->getKey(), $this->items);
    }
    public function merge($items)
    {
        $dictionary = $this->getDictionary();
        foreach ($items as $item) {
            $dictionary[$this->getDictionaryKey($item->getKey())] = $item;
        }
        return new static(array_values($dictionary));
    }
    public function map(callable $callback)
    {
        $result = parent::map($callback);
        return $result->contains(fn($item) => !$item instanceof Model) ? $result->toBase() : $result;
    }
    public function mapWithKeys(callable $callback)
    {
        $result = parent::mapWithKeys($callback);
        return $result->contains(fn($item) => !$item instanceof Model) ? $result->toBase() : $result;
    }
    public function fresh($with = [])
    {
        if ($this->isEmpty()) {
            return new static();
        }
        $model = $this->first();
        $freshModels = $model->newQueryWithoutScopes()->with(is_string($with) ? func_get_args() : $with)->whereIn($model->getKeyName(), $this->modelKeys())->get()->getDictionary();
        return $this->filter(fn($model) => $model->exists && isset($freshModels[$model->getKey()]))->map(fn($model) => $freshModels[$model->getKey()]);
    }
    public function diff($items)
    {
        $diff = new static();
        $dictionary = $this->getDictionary($items);
        foreach ($this->items as $item) {
            if (!isset($dictionary[$this->getDictionaryKey($item->getKey())])) {
                $diff->add($item);
            }
        }
        return $diff;
    }
    public function intersect($items)
    {
        $intersect = new static();
        if (empty($items)) {
            return $intersect;
        }
        $dictionary = $this->getDictionary($items);
        foreach ($this->items as $item) {
            if (isset($dictionary[$this->getDictionaryKey($item->getKey())])) {
                $intersect->add($item);
            }
        }
        return $intersect;
    }
    public function unique($key = null, $strict = false)
    {
        if (!is_null($key)) {
            return parent::unique($key, $strict);
        }
        return new static(array_values($this->getDictionary()));
    }
    public function only($keys)
    {
        if (is_null($keys)) {
            return new static($this->items);
        }
        $dictionary = Arr::only($this->getDictionary(), array_map($this->getDictionaryKey(...), (array) $keys));
        return new static(array_values($dictionary));
    }
    public function except($keys)
    {
        if (is_null($keys)) {
            return new static($this->items);
        }
        $dictionary = Arr::except($this->getDictionary(), array_map($this->getDictionaryKey(...), (array) $keys));
        return new static(array_values($dictionary));
    }
    public function makeHidden($attributes)
    {
        return $this->each->makeHidden($attributes);
    }
    public function makeVisible($attributes)
    {
        return $this->each->makeVisible($attributes);
    }
    public function setVisible($visible)
    {
        return $this->each->setVisible($visible);
    }
    public function setHidden($hidden)
    {
        return $this->each->setHidden($hidden);
    }
    public function append($attributes)
    {
        return $this->each->append($attributes);
    }
    public function getDictionary($items = null)
    {
        $items = is_null($items) ? $this->items : $items;
        $dictionary = [];
        foreach ($items as $value) {
            $dictionary[$this->getDictionaryKey($value->getKey())] = $value;
        }
        return $dictionary;
    }
    public function countBy($countBy = null)
    {
        return $this->toBase()->countBy($countBy);
    }
    public function collapse()
    {
        return $this->toBase()->collapse();
    }
    public function flatten($depth = INF)
    {
        return $this->toBase()->flatten($depth);
    }
    public function flip()
    {
        return $this->toBase()->flip();
    }
    public function keys()
    {
        return $this->toBase()->keys();
    }
    public function pad($size, $value)
    {
        return $this->toBase()->pad($size, $value);
    }
    public function pluck($value, $key = null)
    {
        return $this->toBase()->pluck($value, $key);
    }
    public function zip($items)
    {
        return $this->toBase()->zip(...func_get_args());
    }
    protected function duplicateComparator($strict)
    {
        return fn($a, $b) => $a->is($b);
    }
    public function getQueueableClass()
    {
        if ($this->isEmpty()) {
            return;
        }
        $class = $this->getQueueableModelClass($this->first());
        $this->each(function ($model) use ($class) {
            if ($this->getQueueableModelClass($model) !== $class) {
                throw new LogicException('Queueing collections with multiple model types is not supported.');
            }
        });
        return $class;
    }
    protected function getQueueableModelClass($model)
    {
        return method_exists($model, 'getQueueableClassName') ? $model->getQueueableClassName() : get_class($model);
    }
    public function getQueueableIds()
    {
        if ($this->isEmpty()) {
            return [];
        }
        return $this->first() instanceof QueueableEntity ? $this->map->getQueueableId()->all() : $this->modelKeys();
    }
    public function getQueueableRelations()
    {
        if ($this->isEmpty()) {
            return [];
        }
        $relations = $this->map->getQueueableRelations()->all();
        if (count($relations) === 0 || $relations === [[]]) {
            return [];
        } elseif (count($relations) === 1) {
            return reset($relations);
        } else {
            return array_intersect(...array_values($relations));
        }
    }
    public function getQueueableConnection()
    {
        if ($this->isEmpty()) {
            return;
        }
        $connection = $this->first()->getConnectionName();
        $this->each(function ($model) use ($connection) {
            if ($model->getConnectionName() !== $connection) {
                throw new LogicException('Queueing collections with multiple model connections is not supported.');
            }
        });
        return $connection;
    }
    public function toQuery()
    {
        $model = $this->first();
        if (!$model) {
            throw new LogicException('Unable to create query for empty collection.');
        }
        $class = get_class($model);
        if ($this->filter(fn($model) => !$model instanceof $class)->isNotEmpty()) {
            throw new LogicException('Unable to create query for collection with mixed types.');
        }
        return $model->newModelQuery()->whereKey($this->modelKeys());
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\Command;
class BaseCommand extends Command
{
    protected function getMigrationPaths()
    {
        if ($this->input->hasOption('path') && $this->option('path')) {
            return collect($this->option('path'))->map(function ($path) {
                return !$this->usingRealPath() ? $this->laravel->basePath() . '/' . $path : $path;
            })->all();
        }
        return array_merge($this->migrator->paths(), [$this->getMigrationPath()]);
    }
    protected function usingRealPath()
    {
        return $this->input->hasOption('realpath') && $this->option('realpath');
    }
    protected function getMigrationPath()
    {
        return $this->laravel->databasePath() . DIRECTORY_SEPARATOR . 'migrations';
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\DatabaseRefreshed;
use Symfony\Component\Console\Input\InputOption;
class RefreshCommand extends Command
{
    use ConfirmableTrait;
    protected $name = 'migrate:refresh';
    protected $description = 'Reset and re-run all migrations';
    public function handle()
    {
        if (!$this->confirmToProceed()) {
            return 1;
        }
        $database = $this->input->getOption('database');
        $path = $this->input->getOption('path');
        $step = $this->input->getOption('step') ?: 0;
        if ($step > 0) {
            $this->runRollback($database, $path, $step);
        } else {
            $this->runReset($database, $path);
        }
        $this->call('migrate', array_filter(['--database' => $database, '--path' => $path, '--realpath' => $this->input->getOption('realpath'), '--force' => true]));
        if ($this->laravel->bound(Dispatcher::class)) {
            $this->laravel[Dispatcher::class]->dispatch(new DatabaseRefreshed($database, $this->needsSeeding()));
        }
        if ($this->needsSeeding()) {
            $this->runSeeder($database);
        }
        return 0;
    }
    protected function runRollback($database, $path, $step)
    {
        $this->call('migrate:rollback', array_filter(['--database' => $database, '--path' => $path, '--realpath' => $this->input->getOption('realpath'), '--step' => $step, '--force' => true]));
    }
    protected function runReset($database, $path)
    {
        $this->call('migrate:reset', array_filter(['--database' => $database, '--path' => $path, '--realpath' => $this->input->getOption('realpath'), '--force' => true]));
    }
    protected function needsSeeding()
    {
        return $this->option('seed') || $this->option('seeder');
    }
    protected function runSeeder($database)
    {
        $this->call('db:seed', array_filter(['--database' => $database, '--class' => $this->option('seeder') ?: 'Database\Seeders\DatabaseSeeder', '--force' => true]));
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use'], ['force', null, InputOption::VALUE_NONE, 'Force the operation to run when in production'], ['path', null, InputOption::VALUE_OPTIONAL | InputOption::VALUE_IS_ARRAY, 'The path(s) to the migrations files to be executed'], ['realpath', null, InputOption::VALUE_NONE, 'Indicate any provided migration file paths are pre-resolved absolute paths'], ['seed', null, InputOption::VALUE_NONE, 'Indicates if the seed task should be re-run'], ['seeder', null, InputOption::VALUE_OPTIONAL, 'The class name of the root seeder'], ['step', null, InputOption::VALUE_OPTIONAL, 'The number of migrations to be reverted & re-run']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\ConfirmableTrait;
use Illuminate\Contracts\Console\Isolatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\SchemaLoaded;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Database\SQLiteDatabaseDoesNotExistException;
use Illuminate\Database\SqlServerConnection;
use PDOException;
use Throwable;
use function Laravel\Prompts\confirm;
class MigrateCommand extends BaseCommand implements Isolatable
{
    use ConfirmableTrait;
    protected $signature = 'migrate {--database= : The database connection to use}
                {--force : Force the operation to run when in production}
                {--path=* : The path(s) to the migrations files to be executed}
                {--realpath : Indicate any provided migration file paths are pre-resolved absolute paths}
                {--schema-path= : The path to a schema dump file}
                {--pretend : Dump the SQL queries that would be run}
                {--seed : Indicates if the seed task should be re-run}
                {--seeder= : The class name of the root seeder}
                {--step : Force the migrations to be run so they can be rolled back individually}';
    protected $description = 'Run the database migrations';
    protected $migrator;
    protected $dispatcher;
    public function __construct(Migrator $migrator, Dispatcher $dispatcher)
    {
        parent::__construct();
        $this->migrator = $migrator;
        $this->dispatcher = $dispatcher;
    }
    public function handle()
    {
        if (!$this->confirmToProceed()) {
            return 1;
        }
        $this->migrator->usingConnection($this->option('database'), function () {
            $this->prepareDatabase();
            $this->migrator->setOutput($this->output)->run($this->getMigrationPaths(), ['pretend' => $this->option('pretend'), 'step' => $this->option('step')]);
            if ($this->option('seed') && !$this->option('pretend')) {
                $this->call('db:seed', ['--class' => $this->option('seeder') ?: 'Database\Seeders\DatabaseSeeder', '--force' => true]);
            }
        });
        return 0;
    }
    protected function prepareDatabase()
    {
        if (!$this->repositoryExists()) {
            $this->components->info('Preparing database.');
            $this->components->task('Creating migration table', function () {
                return $this->callSilent('migrate:install', array_filter(['--database' => $this->option('database')])) == 0;
            });
            $this->newLine();
        }
        if (!$this->migrator->hasRunAnyMigrations() && !$this->option('pretend')) {
            $this->loadSchemaState();
        }
    }
    protected function repositoryExists()
    {
        return retry(2, fn() => $this->migrator->repositoryExists(), 0, function ($e) {
            try {
                if ($e->getPrevious() instanceof SQLiteDatabaseDoesNotExistException) {
                    return $this->createMissingSqliteDatabase($e->getPrevious()->path);
                }
                $connection = $this->migrator->resolveConnection($this->option('database'));
                if ($e->getPrevious() instanceof PDOException && $e->getPrevious()->getCode() === 1049 && $connection->getDriverName() === 'mysql') {
                    return $this->createMissingMysqlDatabase($connection);
                }
                return false;
            } catch (Throwable) {
                return false;
            }
        });
    }
    protected function createMissingSqliteDatabase($path)
    {
        if ($this->option('force')) {
            return touch($path);
        }
        if ($this->option('no-interaction')) {
            return false;
        }
        $this->components->warn('The SQLite database does not exist: ' . $path);
        if (!confirm('Would you like to create it?', default: false)) {
            return false;
        }
        return touch($path);
    }
    protected function createMissingMysqlDatabase($connection)
    {
        if ($this->laravel['config']->get("database.connections.{$connection->getName()}.database") !== $connection->getDatabaseName()) {
            return false;
        }
        if (!$this->option('force') && $this->option('no-interaction')) {
            return false;
        }
        if (!$this->option('force') && !$this->option('no-interaction')) {
            $this->components->warn("The database '{$connection->getDatabaseName()}' does not exist on the '{$connection->getName()}' connection.");
            if (!confirm('Would you like to create it?', default: false)) {
                return false;
            }
        }
        try {
            $this->laravel['config']->set("database.connections.{$connection->getName()}.database", null);
            $this->laravel['db']->purge();
            $freshConnection = $this->migrator->resolveConnection($this->option('database'));
            return tap($freshConnection->unprepared("CREATE DATABASE IF NOT EXISTS `{$connection->getDatabaseName()}`"), function () {
                $this->laravel['db']->purge();
            });
        } finally {
            $this->laravel['config']->set("database.connections.{$connection->getName()}.database", $connection->getDatabaseName());
        }
    }
    protected function loadSchemaState()
    {
        $connection = $this->migrator->resolveConnection($this->option('database'));
        if ($connection instanceof SqlServerConnection || !is_file($path = $this->schemaPath($connection))) {
            return;
        }
        $this->components->info('Loading stored database schemas.');
        $this->components->task($path, function () use ($connection, $path) {
            $this->migrator->deleteRepository();
            $connection->getSchemaState()->handleOutputUsing(function ($type, $buffer) {
                $this->output->write($buffer);
            })->load($path);
        });
        $this->newLine();
        $this->dispatcher->dispatch(new SchemaLoaded($connection, $path));
    }
    protected function schemaPath($connection)
    {
        if ($this->option('schema-path')) {
            return $this->option('schema-path');
        }
        if (file_exists($path = database_path('schema/' . $connection->getName() . '-schema.dump'))) {
            return $path;
        }
        return database_path('schema/' . $connection->getName() . '-schema.sql');
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\ConfirmableTrait;
use Illuminate\Database\Migrations\Migrator;
use Symfony\Component\Console\Input\InputOption;
class RollbackCommand extends BaseCommand
{
    use ConfirmableTrait;
    protected $name = 'migrate:rollback';
    protected $description = 'Rollback the last database migration';
    protected $migrator;
    public function __construct(Migrator $migrator)
    {
        parent::__construct();
        $this->migrator = $migrator;
    }
    public function handle()
    {
        if (!$this->confirmToProceed()) {
            return 1;
        }
        $this->migrator->usingConnection($this->option('database'), function () {
            $this->migrator->setOutput($this->output)->rollback($this->getMigrationPaths(), ['pretend' => $this->option('pretend'), 'step' => (int) $this->option('step'), 'batch' => (int) $this->option('batch')]);
        });
        return 0;
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use'], ['force', null, InputOption::VALUE_NONE, 'Force the operation to run when in production'], ['path', null, InputOption::VALUE_OPTIONAL | InputOption::VALUE_IS_ARRAY, 'The path(s) to the migrations files to be executed'], ['realpath', null, InputOption::VALUE_NONE, 'Indicate any provided migration file paths are pre-resolved absolute paths'], ['pretend', null, InputOption::VALUE_NONE, 'Dump the SQL queries that would be run'], ['step', null, InputOption::VALUE_OPTIONAL, 'The number of migrations to be reverted'], ['batch', null, InputOption::VALUE_REQUIRED, 'The batch of migrations (identified by their batch number) to be reverted']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Support\Collection;
use Symfony\Component\Console\Input\InputOption;
class StatusCommand extends BaseCommand
{
    protected $name = 'migrate:status';
    protected $description = 'Show the status of each migration';
    protected $migrator;
    public function __construct(Migrator $migrator)
    {
        parent::__construct();
        $this->migrator = $migrator;
    }
    public function handle()
    {
        return $this->migrator->usingConnection($this->option('database'), function () {
            if (!$this->migrator->repositoryExists()) {
                $this->components->error('Migration table not found.');
                return 1;
            }
            $ran = $this->migrator->getRepository()->getRan();
            $batches = $this->migrator->getRepository()->getMigrationBatches();
            $migrations = $this->getStatusFor($ran, $batches)->when($this->option('pending'), fn($collection) => $collection->filter(function ($migration) {
                return str($migration[1])->contains('Pending');
            }));
            if (count($migrations) > 0) {
                $this->newLine();
                $this->components->twoColumnDetail('<fg=gray>Migration name</>', '<fg=gray>Batch / Status</>');
                $migrations->each(fn($migration) => $this->components->twoColumnDetail($migration[0], $migration[1]));
                $this->newLine();
            } elseif ($this->option('pending')) {
                $this->components->info('No pending migrations');
            } else {
                $this->components->info('No migrations found');
            }
        });
    }
    protected function getStatusFor(array $ran, array $batches)
    {
        return Collection::make($this->getAllMigrationFiles())->map(function ($migration) use ($ran, $batches) {
            $migrationName = $this->migrator->getMigrationName($migration);
            $status = in_array($migrationName, $ran) ? '<fg=green;options=bold>Ran</>' : '<fg=yellow;options=bold>Pending</>';
            if (in_array($migrationName, $ran)) {
                $status = '[' . $batches[$migrationName] . '] ' . $status;
            }
            return [$migrationName, $status];
        });
    }
    protected function getAllMigrationFiles()
    {
        return $this->migrator->getMigrationFiles($this->getMigrationPaths());
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use'], ['pending', null, InputOption::VALUE_NONE, 'Only list pending migrations'], ['path', null, InputOption::VALUE_OPTIONAL | InputOption::VALUE_IS_ARRAY, 'The path(s) to the migrations files to use'], ['realpath', null, InputOption::VALUE_NONE, 'Indicate any provided migration file paths are pre-resolved absolute paths']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Contracts\Console\PromptsForMissingInput;
use Illuminate\Database\Migrations\MigrationCreator;
use Illuminate\Support\Composer;
use Illuminate\Support\Str;
class MigrateMakeCommand extends BaseCommand implements PromptsForMissingInput
{
    protected $signature = 'make:migration {name : The name of the migration}
        {--create= : The table to be created}
        {--table= : The table to migrate}
        {--path= : The location where the migration file should be created}
        {--realpath : Indicate any provided migration file paths are pre-resolved absolute paths}
        {--fullpath : Output the full path of the migration (Deprecated)}';
    protected $description = 'Create a new migration file';
    protected $creator;
    protected $composer;
    public function __construct(MigrationCreator $creator, Composer $composer)
    {
        parent::__construct();
        $this->creator = $creator;
        $this->composer = $composer;
    }
    public function handle()
    {
        $name = Str::snake(trim($this->input->getArgument('name')));
        $table = $this->input->getOption('table');
        $create = $this->input->getOption('create') ?: false;
        if (!$table && is_string($create)) {
            $table = $create;
            $create = true;
        }
        if (!$table) {
            [$table, $create] = TableGuesser::guess($name);
        }
        $this->writeMigration($name, $table, $create);
    }
    protected function writeMigration($name, $table, $create)
    {
        $file = $this->creator->create($name, $this->getMigrationPath(), $table, $create);
        $this->components->info(sprintf('Migration [%s] created successfully.', $file));
    }
    protected function getMigrationPath()
    {
        if (!is_null($targetPath = $this->input->getOption('path'))) {
            return !$this->usingRealPath() ? $this->laravel->basePath() . '/' . $targetPath : $targetPath;
        }
        return parent::getMigrationPath();
    }
    protected function promptForMissingArgumentsUsing()
    {
        return ['name' => ['What should the migration be named?', 'E.g. create_flights_table']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\ConfirmableTrait;
use Illuminate\Database\Migrations\Migrator;
use Symfony\Component\Console\Input\InputOption;
class ResetCommand extends BaseCommand
{
    use ConfirmableTrait;
    protected $name = 'migrate:reset';
    protected $description = 'Rollback all database migrations';
    protected $migrator;
    public function __construct(Migrator $migrator)
    {
        parent::__construct();
        $this->migrator = $migrator;
    }
    public function handle()
    {
        if (!$this->confirmToProceed()) {
            return 1;
        }
        return $this->migrator->usingConnection($this->option('database'), function () {
            if (!$this->migrator->repositoryExists()) {
                return $this->components->warn('Migration table not found.');
            }
            $this->migrator->setOutput($this->output)->reset($this->getMigrationPaths(), $this->option('pretend'));
        });
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use'], ['force', null, InputOption::VALUE_NONE, 'Force the operation to run when in production'], ['path', null, InputOption::VALUE_OPTIONAL | InputOption::VALUE_IS_ARRAY, 'The path(s) to the migrations files to be executed'], ['realpath', null, InputOption::VALUE_NONE, 'Indicate any provided migration file paths are pre-resolved absolute paths'], ['pretend', null, InputOption::VALUE_NONE, 'Dump the SQL queries that would be run']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\Command;
use Illuminate\Database\Migrations\MigrationRepositoryInterface;
use Symfony\Component\Console\Input\InputOption;
class InstallCommand extends Command
{
    protected $name = 'migrate:install';
    protected $description = 'Create the migration repository';
    protected $repository;
    public function __construct(MigrationRepositoryInterface $repository)
    {
        parent::__construct();
        $this->repository = $repository;
    }
    public function handle()
    {
        $this->repository->setSource($this->input->getOption('database'));
        $this->repository->createRepository();
        $this->components->info('Migration table created successfully.');
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use']];
    }
}
}

namespace Illuminate\Database {
use Illuminate\Support\Str;
use Throwable;
trait DetectsLostConnections
{
    protected function causedByLostConnection(Throwable $e)
    {
        $message = $e->getMessage();
        return Str::contains($message, ['server has gone away', 'Server has gone away', 'no connection to the server', 'Lost connection', 'is dead or not enabled', 'Error while sending', 'decryption failed or bad record mac', 'server closed the connection unexpectedly', 'SSL connection has been closed unexpectedly', 'Error writing data to the connection', 'Resource deadlock avoided', 'Transaction() on null', 'child connection forced to terminate due to client_idle_limit', 'query_wait_timeout', 'reset by peer', 'Physical connection is not usable', 'TCP Provider: Error code 0x68', 'ORA-03114', 'Packets out of order. Expected', 'Adaptive Server connection failed', 'Communication link failure', 'connection is no longer usable', 'Login timeout expired', 'SQLSTATE[HY000] [2002] Connection refused', 'running with the --read-only option so it cannot execute this statement', 'The connection is broken and recovery is not possible. The connection is marked by the client driver as unrecoverable. No attempt was made to restore the connection.', 'SQLSTATE[HY000] [2002] php_network_getaddresses: getaddrinfo failed: Try again', 'SQLSTATE[HY000] [2002] php_network_getaddresses: getaddrinfo failed: Name or service not known', 'SQLSTATE[HY000] [2002] php_network_getaddresses: getaddrinfo for', 'SQLSTATE[HY000]: General error: 7 SSL SYSCALL error: EOF detected', 'SQLSTATE[HY000] [2002] Connection timed out', 'SSL: Connection timed out', 'SQLSTATE[HY000]: General error: 1105 The last transaction was aborted due to Seamless Scaling. Please retry.', 'Temporary failure in name resolution', 'SSL: Broken pipe', 'SQLSTATE[08S01]: Communication link failure', 'SQLSTATE[08006] [7] could not connect to server: Connection refused Is the server running on host', 'SQLSTATE[HY000]: General error: 7 SSL SYSCALL error: No route to host', 'The client was disconnected by the server because of inactivity. See wait_timeout and interactive_timeout for configuring this behavior.', 'SQLSTATE[08006] [7] could not translate host name', 'TCP Provider: Error code 0x274C', 'SQLSTATE[HY000] [2002] No such file or directory', 'SSL: Operation timed out', 'Reason: Server is in script upgrade mode. Only administrator can connect at this time.', 'Unknown $curl_error_code: 77', 'SSL: Handshake timed out', 'SSL error: sslv3 alert unexpected message', 'unrecognized SSL error code:', 'SQLSTATE[HY000] [2002] No connection could be made because the target machine actively refused it', 'SQLSTATE[HY000] [2002] A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond', 'SQLSTATE[HY000] [2002] Network is unreachable', 'SQLSTATE[HY000] [2002] The requested address is not valid in its context', 'SQLSTATE[HY000] [2002] A socket operation was attempted to an unreachable network', 'SQLSTATE[HY000]: General error: 3989', 'went away']);
    }
}
}

namespace Illuminate\Database {
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Database\Console\Migrations\FreshCommand;
use Illuminate\Database\Console\Migrations\InstallCommand;
use Illuminate\Database\Console\Migrations\MigrateCommand;
use Illuminate\Database\Console\Migrations\MigrateMakeCommand;
use Illuminate\Database\Console\Migrations\RefreshCommand;
use Illuminate\Database\Console\Migrations\ResetCommand;
use Illuminate\Database\Console\Migrations\RollbackCommand;
use Illuminate\Database\Console\Migrations\StatusCommand;
use Illuminate\Database\Migrations\DatabaseMigrationRepository;
use Illuminate\Database\Migrations\MigrationCreator;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Support\ServiceProvider;
class MigrationServiceProvider extends ServiceProvider implements DeferrableProvider
{
    protected $commands = ['Migrate' => MigrateCommand::class, 'MigrateFresh' => FreshCommand::class, 'MigrateInstall' => InstallCommand::class, 'MigrateRefresh' => RefreshCommand::class, 'MigrateReset' => ResetCommand::class, 'MigrateRollback' => RollbackCommand::class, 'MigrateStatus' => StatusCommand::class, 'MigrateMake' => MigrateMakeCommand::class];
    public function register()
    {
        $this->registerRepository();
        $this->registerMigrator();
        $this->registerCreator();
        $this->registerCommands($this->commands);
    }
    protected function registerRepository()
    {
        $this->app->singleton('migration.repository', function ($app) {
            $table = $app['config']['database.migrations'];
            return new DatabaseMigrationRepository($app['db'], $table);
        });
    }
    protected function registerMigrator()
    {
        $this->app->singleton('migrator', function ($app) {
            $repository = $app['migration.repository'];
            return new Migrator($repository, $app['db'], $app['files'], $app['events']);
        });
    }
    protected function registerCreator()
    {
        $this->app->singleton('migration.creator', function ($app) {
            return new MigrationCreator($app['files'], $app->basePath('stubs'));
        });
    }
    protected function registerCommands(array $commands)
    {
        foreach (array_keys($commands) as $command) {
            $this->{"register{$command}Command"}();
        }
        $this->commands(array_values($commands));
    }
    protected function registerMigrateCommand()
    {
        $this->app->singleton(MigrateCommand::class, function ($app) {
            return new MigrateCommand($app['migrator'], $app[Dispatcher::class]);
        });
    }
    protected function registerMigrateFreshCommand()
    {
        $this->app->singleton(FreshCommand::class);
    }
    protected function registerMigrateInstallCommand()
    {
        $this->app->singleton(InstallCommand::class, function ($app) {
            return new InstallCommand($app['migration.repository']);
        });
    }
    protected function registerMigrateMakeCommand()
    {
        $this->app->singleton(MigrateMakeCommand::class, function ($app) {
            $creator = $app['migration.creator'];
            $composer = $app['composer'];
            return new MigrateMakeCommand($creator, $composer);
        });
    }
    protected function registerMigrateRefreshCommand()
    {
        $this->app->singleton(RefreshCommand::class);
    }
    protected function registerMigrateResetCommand()
    {
        $this->app->singleton(ResetCommand::class, function ($app) {
            return new ResetCommand($app['migrator']);
        });
    }
    protected function registerMigrateRollbackCommand()
    {
        $this->app->singleton(RollbackCommand::class, function ($app) {
            return new RollbackCommand($app['migrator']);
        });
    }
    protected function registerMigrateStatusCommand()
    {
        $this->app->singleton(StatusCommand::class, function ($app) {
            return new StatusCommand($app['migrator']);
        });
    }
    public function provides()
    {
        return array_merge(['migrator', 'migration.repository', 'migration.creator'], array_values($this->commands));
    }
}
}

namespace Illuminate\Database {
use Illuminate\Support\Str;
use PDOException;
use Throwable;
class QueryException extends PDOException
{
    public $connectionName;
    protected $sql;
    protected $bindings;
    public function __construct($connectionName, $sql, array $bindings, Throwable $previous)
    {
        parent::__construct('', 0, $previous);
        $this->connectionName = $connectionName;
        $this->sql = $sql;
        $this->bindings = $bindings;
        $this->code = $previous->getCode();
        $this->message = $this->formatMessage($connectionName, $sql, $bindings, $previous);
        if ($previous instanceof PDOException) {
            $this->errorInfo = $previous->errorInfo;
        }
    }
    protected function formatMessage($connectionName, $sql, $bindings, Throwable $previous)
    {
        return $previous->getMessage() . ' (Connection: ' . $connectionName . ', SQL: ' . Str::replaceArray('?', $bindings, $sql) . ')';
    }
    public function getConnectionName()
    {
        return $this->connectionName;
    }
    public function getSql()
    {
        return $this->sql;
    }
    public function getBindings()
    {
        return $this->bindings;
    }
}
}

namespace Illuminate\Database {
class ConnectionResolver implements ConnectionResolverInterface
{
    protected $connections = [];
    protected $default;
    public function __construct(array $connections = [])
    {
        foreach ($connections as $name => $connection) {
            $this->addConnection($name, $connection);
        }
    }
    public function connection($name = null)
    {
        if (is_null($name)) {
            $name = $this->getDefaultConnection();
        }
        return $this->connections[$name];
    }
    public function addConnection($name, ConnectionInterface $connection)
    {
        $this->connections[$name] = $connection;
    }
    public function hasConnection($name)
    {
        return isset($this->connections[$name]);
    }
    public function getDefaultConnection()
    {
        return $this->default;
    }
    public function setDefaultConnection($name)
    {
        $this->default = $name;
    }
}
}

namespace Illuminate\Encryption {
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use RuntimeException;
class Encrypter implements EncrypterContract, StringEncrypter
{
    protected $key;
    protected $cipher;
    private static $supportedCiphers = ['aes-128-cbc' => ['size' => 16, 'aead' => false], 'aes-256-cbc' => ['size' => 32, 'aead' => false], 'aes-128-gcm' => ['size' => 16, 'aead' => true], 'aes-256-gcm' => ['size' => 32, 'aead' => true]];
    public function __construct($key, $cipher = 'aes-128-cbc')
    {
        $key = (string) $key;
        if (!static::supported($key, $cipher)) {
            $ciphers = implode(', ', array_keys(self::$supportedCiphers));
            throw new RuntimeException("Unsupported cipher or incorrect key length. Supported ciphers are: {$ciphers}.");
        }
        $this->key = $key;
        $this->cipher = $cipher;
    }
    public static function supported($key, $cipher)
    {
        if (!isset(self::$supportedCiphers[strtolower($cipher)])) {
            return false;
        }
        return mb_strlen($key, '8bit') === self::$supportedCiphers[strtolower($cipher)]['size'];
    }
    public static function generateKey($cipher)
    {
        return random_bytes(self::$supportedCiphers[strtolower($cipher)]['size'] ?? 32);
    }
    public function encrypt($value, $serialize = true)
    {
        $iv = random_bytes(openssl_cipher_iv_length(strtolower($this->cipher)));
        $value = \openssl_encrypt($serialize ? serialize($value) : $value, strtolower($this->cipher), $this->key, 0, $iv, $tag);
        if ($value === false) {
            throw new EncryptException('Could not encrypt the data.');
        }
        $iv = base64_encode($iv);
        $tag = base64_encode($tag ?? '');
        $mac = self::$supportedCiphers[strtolower($this->cipher)]['aead'] ? '' : $this->hash($iv, $value);
        $json = json_encode(compact('iv', 'value', 'mac', 'tag'), JSON_UNESCAPED_SLASHES);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncryptException('Could not encrypt the data.');
        }
        return base64_encode($json);
    }
    public function encryptString($value)
    {
        return $this->encrypt($value, false);
    }
    public function decrypt($payload, $unserialize = true)
    {
        $payload = $this->getJsonPayload($payload);
        $iv = base64_decode($payload['iv']);
        $this->ensureTagIsValid($tag = empty($payload['tag']) ? null : base64_decode($payload['tag']));
        $decrypted = \openssl_decrypt($payload['value'], strtolower($this->cipher), $this->key, 0, $iv, $tag ?? '');
        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }
        return $unserialize ? unserialize($decrypted) : $decrypted;
    }
    public function decryptString($payload)
    {
        return $this->decrypt($payload, false);
    }
    protected function hash($iv, $value)
    {
        return hash_hmac('sha256', $iv . $value, $this->key);
    }
    protected function getJsonPayload($payload)
    {
        if (!is_string($payload)) {
            throw new DecryptException('The payload is invalid.');
        }
        $payload = json_decode(base64_decode($payload), true);
        if (!$this->validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }
        if (!self::$supportedCiphers[strtolower($this->cipher)]['aead'] && !$this->validMac($payload)) {
            throw new DecryptException('The MAC is invalid.');
        }
        return $payload;
    }
    protected function validPayload($payload)
    {
        if (!is_array($payload)) {
            return false;
        }
        foreach (['iv', 'value', 'mac'] as $item) {
            if (!isset($payload[$item]) || !is_string($payload[$item])) {
                return false;
            }
        }
        if (isset($payload['tag']) && !is_string($payload['tag'])) {
            return false;
        }
        return strlen(base64_decode($payload['iv'], true)) === openssl_cipher_iv_length(strtolower($this->cipher));
    }
    protected function validMac(array $payload)
    {
        return hash_equals($this->hash($payload['iv'], $payload['value']), $payload['mac']);
    }
    protected function ensureTagIsValid($tag)
    {
        if (self::$supportedCiphers[strtolower($this->cipher)]['aead'] && strlen($tag) !== 16) {
            throw new DecryptException('Could not decrypt the data.');
        }
        if (!self::$supportedCiphers[strtolower($this->cipher)]['aead'] && is_string($tag)) {
            throw new DecryptException('Unable to use tag because the cipher algorithm does not support AEAD.');
        }
    }
    public function getKey()
    {
        return $this->key;
    }
}
}

namespace Illuminate\Encryption {
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Laravel\SerializableClosure\SerializableClosure;
class EncryptionServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->registerEncrypter();
        $this->registerSerializableClosureSecurityKey();
    }
    protected function registerEncrypter()
    {
        $this->app->singleton('encrypter', function ($app) {
            $config = $app->make('config')->get('app');
            return new Encrypter($this->parseKey($config), $config['cipher']);
        });
    }
    protected function registerSerializableClosureSecurityKey()
    {
        $config = $this->app->make('config')->get('app');
        if (!class_exists(SerializableClosure::class) || empty($config['key'])) {
            return;
        }
        SerializableClosure::setSecretKey($this->parseKey($config));
    }
    protected function parseKey(array $config)
    {
        if (Str::startsWith($key = $this->key($config), $prefix = 'base64:')) {
            $key = base64_decode(Str::after($key, $prefix));
        }
        return $key;
    }
    protected function key(array $config)
    {
        return tap($config['key'], function ($key) {
            if (empty($key)) {
                throw new MissingAppKeyException();
            }
        });
    }
}
}

namespace Symfony\Component\Finder {
class SplFileInfo extends \SplFileInfo
{
    private string $relativePath;
    private string $relativePathname;
    public function __construct(string $file, string $relativePath, string $relativePathname)
    {
        parent::__construct($file);
        $this->relativePath = $relativePath;
        $this->relativePathname = $relativePathname;
    }
    public function getRelativePath(): string
    {
        return $this->relativePath;
    }
    public function getRelativePathname(): string
    {
        return $this->relativePathname;
    }
    public function getFilenameWithoutExtension(): string
    {
        $filename = $this->getFilename();
        return pathinfo($filename, \PATHINFO_FILENAME);
    }
    public function getContents(): string
    {
        set_error_handler(function ($type, $msg) use (&$error) {
            $error = $msg;
        });
        try {
            $content = file_get_contents($this->getPathname());
        } finally {
            restore_error_handler();
        }
        if (false === $content) {
            throw new \RuntimeException($error);
        }
        return $content;
    }
}
}

namespace Symfony\Component\Finder\Iterator {
abstract class MultiplePcreFilterIterator extends \FilterIterator
{
    protected $matchRegexps = [];
    protected $noMatchRegexps = [];
    public function __construct(\Iterator $iterator, array $matchPatterns, array $noMatchPatterns)
    {
        foreach ($matchPatterns as $pattern) {
            $this->matchRegexps[] = $this->toRegex($pattern);
        }
        foreach ($noMatchPatterns as $pattern) {
            $this->noMatchRegexps[] = $this->toRegex($pattern);
        }
        parent::__construct($iterator);
    }
    protected function isAccepted(string $string): bool
    {
        foreach ($this->noMatchRegexps as $regex) {
            if (preg_match($regex, $string)) {
                return false;
            }
        }
        if ($this->matchRegexps) {
            foreach ($this->matchRegexps as $regex) {
                if (preg_match($regex, $string)) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }
    protected function isRegex(string $str): bool
    {
        $availableModifiers = 'imsxuADU';
        if (\PHP_VERSION_ID >= 80200) {
            $availableModifiers .= 'n';
        }
        if (preg_match('/^(.{3,}?)[' . $availableModifiers . ']*$/', $str, $m)) {
            $start = substr($m[1], 0, 1);
            $end = substr($m[1], -1);
            if ($start === $end) {
                return !preg_match('/[*?[:alnum:] \\\\]/', $start);
            }
            foreach ([['{', '}'], ['(', ')'], ['[', ']'], ['<', '>']] as $delimiters) {
                if ($start === $delimiters[0] && $end === $delimiters[1]) {
                    return true;
                }
            }
        }
        return false;
    }
    abstract protected function toRegex(string $str): string;
}
}

namespace Symfony\Component\Finder\Iterator {
use Symfony\Component\Finder\SplFileInfo;
class PathFilterIterator extends MultiplePcreFilterIterator
{
    public function accept(): bool
    {
        $filename = $this->current()->getRelativePathname();
        if ('\\' === \DIRECTORY_SEPARATOR) {
            $filename = str_replace('\\', '/', $filename);
        }
        return $this->isAccepted($filename);
    }
    protected function toRegex(string $str): string
    {
        return $this->isRegex($str) ? $str : '/' . preg_quote($str, '/') . '/';
    }
}
}

namespace Symfony\Component\Finder\Iterator {
use Symfony\Component\Finder\SplFileInfo;
class ExcludeDirectoryFilterIterator extends \FilterIterator implements \RecursiveIterator
{
    private \Iterator $iterator;
    private bool $isRecursive;
    private array $excludedDirs = [];
    private ?string $excludedPattern = null;
    private array $pruneFilters = [];
    public function __construct(\Iterator $iterator, array $directories)
    {
        $this->iterator = $iterator;
        $this->isRecursive = $iterator instanceof \RecursiveIterator;
        $patterns = [];
        foreach ($directories as $directory) {
            if (!\is_string($directory)) {
                if (!\is_callable($directory)) {
                    throw new \InvalidArgumentException('Invalid PHP callback.');
                }
                $this->pruneFilters[] = $directory;
                continue;
            }
            $directory = rtrim($directory, '/');
            if (!$this->isRecursive || str_contains($directory, '/')) {
                $patterns[] = preg_quote($directory, '#');
            } else {
                $this->excludedDirs[$directory] = true;
            }
        }
        if ($patterns) {
            $this->excludedPattern = '#(?:^|/)(?:' . implode('|', $patterns) . ')(?:/|$)#';
        }
        parent::__construct($iterator);
    }
    public function accept(): bool
    {
        if ($this->isRecursive && isset($this->excludedDirs[$this->getFilename()]) && $this->isDir()) {
            return false;
        }
        if ($this->excludedPattern) {
            $path = $this->isDir() ? $this->current()->getRelativePathname() : $this->current()->getRelativePath();
            $path = str_replace('\\', '/', $path);
            return !preg_match($this->excludedPattern, $path);
        }
        if ($this->pruneFilters && $this->hasChildren()) {
            foreach ($this->pruneFilters as $pruneFilter) {
                if (!$pruneFilter($this->current())) {
                    return false;
                }
            }
        }
        return true;
    }
    public function hasChildren(): bool
    {
        return $this->isRecursive && $this->iterator->hasChildren();
    }
    public function getChildren(): self
    {
        $children = new self($this->iterator->getChildren(), []);
        $children->excludedDirs = $this->excludedDirs;
        $children->excludedPattern = $this->excludedPattern;
        return $children;
    }
}
}

namespace Symfony\Component\Finder\Iterator {
use Symfony\Component\Finder\Exception\AccessDeniedException;
use Symfony\Component\Finder\SplFileInfo;
class RecursiveDirectoryIterator extends \RecursiveDirectoryIterator
{
    private bool $ignoreUnreadableDirs;
    private bool $ignoreFirstRewind = true;
    private string $rootPath;
    private string $subPath;
    private string $directorySeparator = '/';
    public function __construct(string $path, int $flags, bool $ignoreUnreadableDirs = false)
    {
        if ($flags & (self::CURRENT_AS_PATHNAME | self::CURRENT_AS_SELF)) {
            throw new \RuntimeException('This iterator only support returning current as fileinfo.');
        }
        parent::__construct($path, $flags);
        $this->ignoreUnreadableDirs = $ignoreUnreadableDirs;
        $this->rootPath = $path;
        if ('/' !== \DIRECTORY_SEPARATOR && !($flags & self::UNIX_PATHS)) {
            $this->directorySeparator = \DIRECTORY_SEPARATOR;
        }
    }
    public function current(): SplFileInfo
    {
        if (!isset($this->subPath)) {
            $this->subPath = $this->getSubPath();
        }
        $subPathname = $this->subPath;
        if ('' !== $subPathname) {
            $subPathname .= $this->directorySeparator;
        }
        $subPathname .= $this->getFilename();
        $basePath = $this->rootPath;
        if ('/' !== $basePath && !str_ends_with($basePath, $this->directorySeparator) && !str_ends_with($basePath, '/')) {
            $basePath .= $this->directorySeparator;
        }
        return new SplFileInfo($basePath . $subPathname, $this->subPath, $subPathname);
    }
    public function hasChildren(bool $allowLinks = false): bool
    {
        $hasChildren = parent::hasChildren($allowLinks);
        if (!$hasChildren || !$this->ignoreUnreadableDirs) {
            return $hasChildren;
        }
        try {
            parent::getChildren();
            return true;
        } catch (\UnexpectedValueException) {
            return false;
        }
    }
    public function getChildren(): \RecursiveDirectoryIterator
    {
        try {
            $children = parent::getChildren();
            if ($children instanceof self) {
                $children->ignoreUnreadableDirs = $this->ignoreUnreadableDirs;
                $children->rootPath = $this->rootPath;
            }
            return $children;
        } catch (\UnexpectedValueException $e) {
            throw new AccessDeniedException($e->getMessage(), $e->getCode(), $e);
        }
    }
    public function next(): void
    {
        $this->ignoreFirstRewind = false;
        parent::next();
    }
    public function rewind(): void
    {
        if ($this->ignoreFirstRewind) {
            $this->ignoreFirstRewind = false;
            return;
        }
        parent::rewind();
    }
}
}

namespace Symfony\Component\Finder\Iterator {
class FileTypeFilterIterator extends \FilterIterator
{
    public const ONLY_FILES = 1;
    public const ONLY_DIRECTORIES = 2;
    private int $mode;
    public function __construct(\Iterator $iterator, int $mode)
    {
        $this->mode = $mode;
        parent::__construct($iterator);
    }
    public function accept(): bool
    {
        $fileinfo = $this->current();
        if (self::ONLY_DIRECTORIES === (self::ONLY_DIRECTORIES & $this->mode) && $fileinfo->isFile()) {
            return false;
        } elseif (self::ONLY_FILES === (self::ONLY_FILES & $this->mode) && $fileinfo->isDir()) {
            return false;
        }
        return true;
    }
}
}

namespace Symfony\Component\Finder\Iterator {
use Symfony\Component\Finder\Glob;
class FilenameFilterIterator extends MultiplePcreFilterIterator
{
    public function accept(): bool
    {
        return $this->isAccepted($this->current()->getFilename());
    }
    protected function toRegex(string $str): string
    {
        return $this->isRegex($str) ? $str : Glob::toRegex($str);
    }
}
}

namespace Symfony\Component\Finder {
use Symfony\Component\Finder\Comparator\DateComparator;
use Symfony\Component\Finder\Comparator\NumberComparator;
use Symfony\Component\Finder\Exception\DirectoryNotFoundException;
use Symfony\Component\Finder\Iterator\CustomFilterIterator;
use Symfony\Component\Finder\Iterator\DateRangeFilterIterator;
use Symfony\Component\Finder\Iterator\DepthRangeFilterIterator;
use Symfony\Component\Finder\Iterator\ExcludeDirectoryFilterIterator;
use Symfony\Component\Finder\Iterator\FilecontentFilterIterator;
use Symfony\Component\Finder\Iterator\FilenameFilterIterator;
use Symfony\Component\Finder\Iterator\LazyIterator;
use Symfony\Component\Finder\Iterator\SizeRangeFilterIterator;
use Symfony\Component\Finder\Iterator\SortableIterator;
class Finder implements \IteratorAggregate, \Countable
{
    public const IGNORE_VCS_FILES = 1;
    public const IGNORE_DOT_FILES = 2;
    public const IGNORE_VCS_IGNORED_FILES = 4;
    private int $mode = 0;
    private array $names = [];
    private array $notNames = [];
    private array $exclude = [];
    private array $filters = [];
    private array $pruneFilters = [];
    private array $depths = [];
    private array $sizes = [];
    private bool $followLinks = false;
    private bool $reverseSorting = false;
    private \Closure|int|false $sort = false;
    private int $ignore = 0;
    private array $dirs = [];
    private array $dates = [];
    private array $iterators = [];
    private array $contains = [];
    private array $notContains = [];
    private array $paths = [];
    private array $notPaths = [];
    private bool $ignoreUnreadableDirs = false;
    private static array $vcsPatterns = ['.svn', '_svn', 'CVS', '_darcs', '.arch-params', '.monotone', '.bzr', '.git', '.hg'];
    public function __construct()
    {
        $this->ignore = static::IGNORE_VCS_FILES | static::IGNORE_DOT_FILES;
    }
    public static function create(): static
    {
        return new static();
    }
    public function directories(): static
    {
        $this->mode = Iterator\FileTypeFilterIterator::ONLY_DIRECTORIES;
        return $this;
    }
    public function files(): static
    {
        $this->mode = Iterator\FileTypeFilterIterator::ONLY_FILES;
        return $this;
    }
    public function depth(string|int|array $levels): static
    {
        foreach ((array) $levels as $level) {
            $this->depths[] = new Comparator\NumberComparator($level);
        }
        return $this;
    }
    public function date(string|array $dates): static
    {
        foreach ((array) $dates as $date) {
            $this->dates[] = new Comparator\DateComparator($date);
        }
        return $this;
    }
    public function name(string|array $patterns): static
    {
        $this->names = array_merge($this->names, (array) $patterns);
        return $this;
    }
    public function notName(string|array $patterns): static
    {
        $this->notNames = array_merge($this->notNames, (array) $patterns);
        return $this;
    }
    public function contains(string|array $patterns): static
    {
        $this->contains = array_merge($this->contains, (array) $patterns);
        return $this;
    }
    public function notContains(string|array $patterns): static
    {
        $this->notContains = array_merge($this->notContains, (array) $patterns);
        return $this;
    }
    public function path(string|array $patterns): static
    {
        $this->paths = array_merge($this->paths, (array) $patterns);
        return $this;
    }
    public function notPath(string|array $patterns): static
    {
        $this->notPaths = array_merge($this->notPaths, (array) $patterns);
        return $this;
    }
    public function size(string|int|array $sizes): static
    {
        foreach ((array) $sizes as $size) {
            $this->sizes[] = new Comparator\NumberComparator($size);
        }
        return $this;
    }
    public function exclude(string|array $dirs): static
    {
        $this->exclude = array_merge($this->exclude, (array) $dirs);
        return $this;
    }
    public function ignoreDotFiles(bool $ignoreDotFiles): static
    {
        if ($ignoreDotFiles) {
            $this->ignore |= static::IGNORE_DOT_FILES;
        } else {
            $this->ignore &= ~static::IGNORE_DOT_FILES;
        }
        return $this;
    }
    public function ignoreVCS(bool $ignoreVCS): static
    {
        if ($ignoreVCS) {
            $this->ignore |= static::IGNORE_VCS_FILES;
        } else {
            $this->ignore &= ~static::IGNORE_VCS_FILES;
        }
        return $this;
    }
    public function ignoreVCSIgnored(bool $ignoreVCSIgnored): static
    {
        if ($ignoreVCSIgnored) {
            $this->ignore |= static::IGNORE_VCS_IGNORED_FILES;
        } else {
            $this->ignore &= ~static::IGNORE_VCS_IGNORED_FILES;
        }
        return $this;
    }
    public static function addVCSPattern(string|array $pattern)
    {
        foreach ((array) $pattern as $p) {
            self::$vcsPatterns[] = $p;
        }
        self::$vcsPatterns = array_unique(self::$vcsPatterns);
    }
    public function sort(\Closure $closure): static
    {
        $this->sort = $closure;
        return $this;
    }
    public function sortByExtension(): static
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_EXTENSION;
        return $this;
    }
    public function sortByName(bool $useNaturalSort = false): static
    {
        $this->sort = $useNaturalSort ? Iterator\SortableIterator::SORT_BY_NAME_NATURAL : Iterator\SortableIterator::SORT_BY_NAME;
        return $this;
    }
    public function sortByCaseInsensitiveName(bool $useNaturalSort = false): static
    {
        $this->sort = $useNaturalSort ? Iterator\SortableIterator::SORT_BY_NAME_NATURAL_CASE_INSENSITIVE : Iterator\SortableIterator::SORT_BY_NAME_CASE_INSENSITIVE;
        return $this;
    }
    public function sortBySize(): static
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_SIZE;
        return $this;
    }
    public function sortByType(): static
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_TYPE;
        return $this;
    }
    public function sortByAccessedTime(): static
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_ACCESSED_TIME;
        return $this;
    }
    public function reverseSorting(): static
    {
        $this->reverseSorting = true;
        return $this;
    }
    public function sortByChangedTime(): static
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_CHANGED_TIME;
        return $this;
    }
    public function sortByModifiedTime(): static
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_MODIFIED_TIME;
        return $this;
    }
    public function filter(\Closure $closure): static
    {
        $prune = 1 < \func_num_args() ? func_get_arg(1) : false;
        $this->filters[] = $closure;
        if ($prune) {
            $this->pruneFilters[] = $closure;
        }
        return $this;
    }
    public function followLinks(): static
    {
        $this->followLinks = true;
        return $this;
    }
    public function ignoreUnreadableDirs(bool $ignore = true): static
    {
        $this->ignoreUnreadableDirs = $ignore;
        return $this;
    }
    public function in(string|array $dirs): static
    {
        $resolvedDirs = [];
        foreach ((array) $dirs as $dir) {
            if (is_dir($dir)) {
                $resolvedDirs[] = [$this->normalizeDir($dir)];
            } elseif ($glob = glob($dir, (\defined('GLOB_BRACE') ? \GLOB_BRACE : 0) | \GLOB_ONLYDIR | \GLOB_NOSORT)) {
                sort($glob);
                $resolvedDirs[] = array_map($this->normalizeDir(...), $glob);
            } else {
                throw new DirectoryNotFoundException(sprintf('The "%s" directory does not exist.', $dir));
            }
        }
        $this->dirs = array_merge($this->dirs, ...$resolvedDirs);
        return $this;
    }
    public function getIterator(): \Iterator
    {
        if (0 === \count($this->dirs) && 0 === \count($this->iterators)) {
            throw new \LogicException('You must call one of in() or append() methods before iterating over a Finder.');
        }
        if (1 === \count($this->dirs) && 0 === \count($this->iterators)) {
            $iterator = $this->searchInDirectory($this->dirs[0]);
            if ($this->sort || $this->reverseSorting) {
                $iterator = (new Iterator\SortableIterator($iterator, $this->sort, $this->reverseSorting))->getIterator();
            }
            return $iterator;
        }
        $iterator = new \AppendIterator();
        foreach ($this->dirs as $dir) {
            $iterator->append(new \IteratorIterator(new LazyIterator(fn() => $this->searchInDirectory($dir))));
        }
        foreach ($this->iterators as $it) {
            $iterator->append($it);
        }
        if ($this->sort || $this->reverseSorting) {
            $iterator = (new Iterator\SortableIterator($iterator, $this->sort, $this->reverseSorting))->getIterator();
        }
        return $iterator;
    }
    public function append(iterable $iterator): static
    {
        if ($iterator instanceof \IteratorAggregate) {
            $this->iterators[] = $iterator->getIterator();
        } elseif ($iterator instanceof \Iterator) {
            $this->iterators[] = $iterator;
        } elseif (is_iterable($iterator)) {
            $it = new \ArrayIterator();
            foreach ($iterator as $file) {
                $file = $file instanceof \SplFileInfo ? $file : new \SplFileInfo($file);
                $it[$file->getPathname()] = $file;
            }
            $this->iterators[] = $it;
        } else {
            throw new \InvalidArgumentException('Finder::append() method wrong argument type.');
        }
        return $this;
    }
    public function hasResults(): bool
    {
        foreach ($this->getIterator() as $_) {
            return true;
        }
        return false;
    }
    public function count(): int
    {
        return iterator_count($this->getIterator());
    }
    private function searchInDirectory(string $dir): \Iterator
    {
        $exclude = $this->exclude;
        $notPaths = $this->notPaths;
        if ($this->pruneFilters) {
            $exclude = array_merge($exclude, $this->pruneFilters);
        }
        if (static::IGNORE_VCS_FILES === (static::IGNORE_VCS_FILES & $this->ignore)) {
            $exclude = array_merge($exclude, self::$vcsPatterns);
        }
        if (static::IGNORE_DOT_FILES === (static::IGNORE_DOT_FILES & $this->ignore)) {
            $notPaths[] = '#(^|/)\..+(/|$)#';
        }
        $minDepth = 0;
        $maxDepth = \PHP_INT_MAX;
        foreach ($this->depths as $comparator) {
            switch ($comparator->getOperator()) {
                case '>':
                    $minDepth = $comparator->getTarget() + 1;
                    break;
                case '>=':
                    $minDepth = $comparator->getTarget();
                    break;
                case '<':
                    $maxDepth = $comparator->getTarget() - 1;
                    break;
                case '<=':
                    $maxDepth = $comparator->getTarget();
                    break;
                default:
                    $minDepth = $maxDepth = $comparator->getTarget();
            }
        }
        $flags = \RecursiveDirectoryIterator::SKIP_DOTS;
        if ($this->followLinks) {
            $flags |= \RecursiveDirectoryIterator::FOLLOW_SYMLINKS;
        }
        $iterator = new Iterator\RecursiveDirectoryIterator($dir, $flags, $this->ignoreUnreadableDirs);
        if ($exclude) {
            $iterator = new Iterator\ExcludeDirectoryFilterIterator($iterator, $exclude);
        }
        $iterator = new \RecursiveIteratorIterator($iterator, \RecursiveIteratorIterator::SELF_FIRST);
        if ($minDepth > 0 || $maxDepth < \PHP_INT_MAX) {
            $iterator = new Iterator\DepthRangeFilterIterator($iterator, $minDepth, $maxDepth);
        }
        if ($this->mode) {
            $iterator = new Iterator\FileTypeFilterIterator($iterator, $this->mode);
        }
        if ($this->names || $this->notNames) {
            $iterator = new Iterator\FilenameFilterIterator($iterator, $this->names, $this->notNames);
        }
        if ($this->contains || $this->notContains) {
            $iterator = new Iterator\FilecontentFilterIterator($iterator, $this->contains, $this->notContains);
        }
        if ($this->sizes) {
            $iterator = new Iterator\SizeRangeFilterIterator($iterator, $this->sizes);
        }
        if ($this->dates) {
            $iterator = new Iterator\DateRangeFilterIterator($iterator, $this->dates);
        }
        if ($this->filters) {
            $iterator = new Iterator\CustomFilterIterator($iterator, $this->filters);
        }
        if ($this->paths || $notPaths) {
            $iterator = new Iterator\PathFilterIterator($iterator, $this->paths, $notPaths);
        }
        if (static::IGNORE_VCS_IGNORED_FILES === (static::IGNORE_VCS_IGNORED_FILES & $this->ignore)) {
            $iterator = new Iterator\VcsIgnoredFilterIterator($iterator, $dir);
        }
        return $iterator;
    }
    private function normalizeDir(string $dir): string
    {
        if ('/' === $dir) {
            return $dir;
        }
        $dir = rtrim($dir, '/' . \DIRECTORY_SEPARATOR);
        if (preg_match('#^(ssh2\.)?s?ftp://#', $dir)) {
            $dir .= '/';
        }
        return $dir;
    }
}
}

namespace Symfony\Component\Finder {
class Glob
{
    public static function toRegex(string $glob, bool $strictLeadingDot = true, bool $strictWildcardSlash = true, string $delimiter = '#'): string
    {
        $firstByte = true;
        $escaping = false;
        $inCurlies = 0;
        $regex = '';
        $sizeGlob = \strlen($glob);
        for ($i = 0; $i < $sizeGlob; ++$i) {
            $car = $glob[$i];
            if ($firstByte && $strictLeadingDot && '.' !== $car) {
                $regex .= '(?=[^\.])';
            }
            $firstByte = '/' === $car;
            if ($firstByte && $strictWildcardSlash && isset($glob[$i + 2]) && '**' === $glob[$i + 1] . $glob[$i + 2] && (!isset($glob[$i + 3]) || '/' === $glob[$i + 3])) {
                $car = '[^/]++/';
                if (!isset($glob[$i + 3])) {
                    $car .= '?';
                }
                if ($strictLeadingDot) {
                    $car = '(?=[^\.])' . $car;
                }
                $car = '/(?:' . $car . ')*';
                $i += 2 + isset($glob[$i + 3]);
                if ('/' === $delimiter) {
                    $car = str_replace('/', '\/', $car);
                }
            }
            if ($delimiter === $car || '.' === $car || '(' === $car || ')' === $car || '|' === $car || '+' === $car || '^' === $car || '$' === $car) {
                $regex .= "\\{$car}";
            } elseif ('*' === $car) {
                $regex .= $escaping ? '\*' : ($strictWildcardSlash ? '[^/]*' : '.*');
            } elseif ('?' === $car) {
                $regex .= $escaping ? '\?' : ($strictWildcardSlash ? '[^/]' : '.');
            } elseif ('{' === $car) {
                $regex .= $escaping ? '\{' : '(';
                if (!$escaping) {
                    ++$inCurlies;
                }
            } elseif ('}' === $car && $inCurlies) {
                $regex .= $escaping ? '}' : ')';
                if (!$escaping) {
                    --$inCurlies;
                }
            } elseif (',' === $car && $inCurlies) {
                $regex .= $escaping ? ',' : '|';
            } elseif ('\\' === $car) {
                if ($escaping) {
                    $regex .= '\\\\';
                    $escaping = false;
                } else {
                    $escaping = true;
                }
                continue;
            } else {
                $regex .= $car;
            }
            $escaping = false;
        }
        return $delimiter . '^' . $regex . '$' . $delimiter;
    }
}
}

namespace Carbon {
use Carbon\Traits\Date;
use Carbon\Traits\DeprecatedProperties;
use DateTime;
use DateTimeInterface;
use DateTimeZone;
class Carbon extends DateTime implements CarbonInterface
{
    use Date;
    public static function isMutable()
    {
        return true;
    }
}
}

namespace FastRoute\RouteParser {
use FastRoute\BadRouteException;
use FastRoute\RouteParser;
class Std implements RouteParser
{
    const VARIABLE_REGEX = <<<'REGEX'
    \{
        \s* ([a-zA-Z_][a-zA-Z0-9_-]*) \s*
        (?:
            : \s* ([^{}]*(?:\{(?-1)\}[^{}]*)*)
        )?
    \}
    REGEX;
    const DEFAULT_DISPATCH_REGEX = '[^/]+';
    public function parse($route)
    {
        $routeWithoutClosingOptionals = rtrim($route, ']');
        $numOptionals = strlen($route) - strlen($routeWithoutClosingOptionals);
        $segments = preg_split('~' . self::VARIABLE_REGEX . '(*SKIP)(*F) | \[~x', $routeWithoutClosingOptionals);
        if ($numOptionals !== count($segments) - 1) {
            if (preg_match('~' . self::VARIABLE_REGEX . '(*SKIP)(*F) | \]~x', $routeWithoutClosingOptionals)) {
                throw new BadRouteException('Optional segments can only occur at the end of a route');
            }
            throw new BadRouteException("Number of opening '[' and closing ']' does not match");
        }
        $currentRoute = '';
        $routeDatas = [];
        foreach ($segments as $n => $segment) {
            if ($segment === '' && $n !== 0) {
                throw new BadRouteException('Empty optional part');
            }
            $currentRoute .= $segment;
            $routeDatas[] = $this->parsePlaceholders($currentRoute);
        }
        return $routeDatas;
    }
    private function parsePlaceholders($route)
    {
        if (!preg_match_all('~' . self::VARIABLE_REGEX . '~x', $route, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
            return [$route];
        }
        $offset = 0;
        $routeData = [];
        foreach ($matches as $set) {
            if ($set[0][1] > $offset) {
                $routeData[] = substr($route, $offset, $set[0][1] - $offset);
            }
            $routeData[] = [$set[1][0], isset($set[2]) ? trim($set[2][0]) : self::DEFAULT_DISPATCH_REGEX];
            $offset = $set[0][1] + strlen($set[0][0]);
        }
        if ($offset !== strlen($route)) {
            $routeData[] = substr($route, $offset);
        }
        return $routeData;
    }
}
}

namespace FastRoute {
class BadRouteException extends \LogicException
{
}
}

namespace FastRoute\DataGenerator {
use FastRoute\BadRouteException;
use FastRoute\DataGenerator;
use FastRoute\Route;
abstract class RegexBasedAbstract implements DataGenerator
{
    protected $staticRoutes = [];
    protected $methodToRegexToRoutesMap = [];
    abstract protected function getApproxChunkSize();
    abstract protected function processChunk($regexToRoutesMap);
    public function addRoute($httpMethod, $routeData, $handler)
    {
        if ($this->isStaticRoute($routeData)) {
            $this->addStaticRoute($httpMethod, $routeData, $handler);
        } else {
            $this->addVariableRoute($httpMethod, $routeData, $handler);
        }
    }
    public function getData()
    {
        if (empty($this->methodToRegexToRoutesMap)) {
            return [$this->staticRoutes, []];
        }
        return [$this->staticRoutes, $this->generateVariableRouteData()];
    }
    private function generateVariableRouteData()
    {
        $data = [];
        foreach ($this->methodToRegexToRoutesMap as $method => $regexToRoutesMap) {
            $chunkSize = $this->computeChunkSize(count($regexToRoutesMap));
            $chunks = array_chunk($regexToRoutesMap, $chunkSize, true);
            $data[$method] = array_map([$this, 'processChunk'], $chunks);
        }
        return $data;
    }
    private function computeChunkSize($count)
    {
        $numParts = max(1, round($count / $this->getApproxChunkSize()));
        return (int) ceil($count / $numParts);
    }
    private function isStaticRoute($routeData)
    {
        return count($routeData) === 1 && is_string($routeData[0]);
    }
    private function addStaticRoute($httpMethod, $routeData, $handler)
    {
        $routeStr = $routeData[0];
        if (isset($this->staticRoutes[$httpMethod][$routeStr])) {
            throw new BadRouteException(sprintf('Cannot register two routes matching "%s" for method "%s"', $routeStr, $httpMethod));
        }
        if (isset($this->methodToRegexToRoutesMap[$httpMethod])) {
            foreach ($this->methodToRegexToRoutesMap[$httpMethod] as $route) {
                if ($route->matches($routeStr)) {
                    throw new BadRouteException(sprintf('Static route "%s" is shadowed by previously defined variable route "%s" for method "%s"', $routeStr, $route->regex, $httpMethod));
                }
            }
        }
        $this->staticRoutes[$httpMethod][$routeStr] = $handler;
    }
    private function addVariableRoute($httpMethod, $routeData, $handler)
    {
        list($regex, $variables) = $this->buildRegexForRoute($routeData);
        if (isset($this->methodToRegexToRoutesMap[$httpMethod][$regex])) {
            throw new BadRouteException(sprintf('Cannot register two routes matching "%s" for method "%s"', $regex, $httpMethod));
        }
        $this->methodToRegexToRoutesMap[$httpMethod][$regex] = new Route($httpMethod, $handler, $regex, $variables);
    }
    private function buildRegexForRoute($routeData)
    {
        $regex = '';
        $variables = [];
        foreach ($routeData as $part) {
            if (is_string($part)) {
                $regex .= preg_quote($part, '~');
                continue;
            }
            list($varName, $regexPart) = $part;
            if (isset($variables[$varName])) {
                throw new BadRouteException(sprintf('Cannot use the same placeholder "%s" twice', $varName));
            }
            if ($this->regexHasCapturingGroups($regexPart)) {
                throw new BadRouteException(sprintf('Regex "%s" for parameter "%s" contains a capturing group', $regexPart, $varName));
            }
            $variables[$varName] = $varName;
            $regex .= '(' . $regexPart . ')';
        }
        return [$regex, $variables];
    }
    private function regexHasCapturingGroups($regex)
    {
        if (false === strpos($regex, '(')) {
            return false;
        }
        return (bool) preg_match('~
                (?:
                    \(\?\(
                  | \[ [^\]\\\\]* (?: \\\\ . [^\]\\\\]* )* \]
                  | \\\\ .
                ) (*SKIP)(*FAIL) |
                \(
                (?!
                    \? (?! <(?![!=]) | P< | \' )
                  | \*
                )
            ~x', $regex);
    }
}
}

namespace FastRoute\DataGenerator {
class MarkBased extends RegexBasedAbstract
{
    protected function getApproxChunkSize()
    {
        return 30;
    }
    protected function processChunk($regexToRoutesMap)
    {
        $routeMap = [];
        $regexes = [];
        $markName = 'a';
        foreach ($regexToRoutesMap as $regex => $route) {
            $regexes[] = $regex . '(*MARK:' . $markName . ')';
            $routeMap[$markName] = [$route->handler, $route->variables];
            ++$markName;
        }
        $regex = '~^(?|' . implode('|', $regexes) . ')$~';
        return ['regex' => $regex, 'routeMap' => $routeMap];
    }
}
}

namespace FastRoute\DataGenerator {
class GroupPosBased extends RegexBasedAbstract
{
    protected function getApproxChunkSize()
    {
        return 10;
    }
    protected function processChunk($regexToRoutesMap)
    {
        $routeMap = [];
        $regexes = [];
        $offset = 1;
        foreach ($regexToRoutesMap as $regex => $route) {
            $regexes[] = $regex;
            $routeMap[$offset] = [$route->handler, $route->variables];
            $offset += count($route->variables);
        }
        $regex = '~^(?:' . implode('|', $regexes) . ')$~';
        return ['regex' => $regex, 'routeMap' => $routeMap];
    }
}
}

namespace FastRoute\DataGenerator {
class GroupCountBased extends RegexBasedAbstract
{
    protected function getApproxChunkSize()
    {
        return 10;
    }
    protected function processChunk($regexToRoutesMap)
    {
        $routeMap = [];
        $regexes = [];
        $numGroups = 0;
        foreach ($regexToRoutesMap as $regex => $route) {
            $numVariables = count($route->variables);
            $numGroups = max($numGroups, $numVariables);
            $regexes[] = $regex . str_repeat('()', $numGroups - $numVariables);
            $routeMap[$numGroups + 1] = [$route->handler, $route->variables];
            ++$numGroups;
        }
        $regex = '~^(?|' . implode('|', $regexes) . ')$~';
        return ['regex' => $regex, 'routeMap' => $routeMap];
    }
}
}

namespace FastRoute\DataGenerator {
class CharCountBased extends RegexBasedAbstract
{
    protected function getApproxChunkSize()
    {
        return 30;
    }
    protected function processChunk($regexToRoutesMap)
    {
        $routeMap = [];
        $regexes = [];
        $suffixLen = 0;
        $suffix = '';
        $count = count($regexToRoutesMap);
        foreach ($regexToRoutesMap as $regex => $route) {
            $suffixLen++;
            $suffix .= "\t";
            $regexes[] = '(?:' . $regex . '/(\t{' . $suffixLen . '})\t{' . ($count - $suffixLen) . '})';
            $routeMap[$suffix] = [$route->handler, $route->variables];
        }
        $regex = '~^(?|' . implode('|', $regexes) . ')$~';
        return ['regex' => $regex, 'suffix' => '/' . $suffix, 'routeMap' => $routeMap];
    }
}
}

namespace FastRoute {
class RouteCollector
{
    protected $routeParser;
    protected $dataGenerator;
    protected $currentGroupPrefix;
    public function __construct(RouteParser $routeParser, DataGenerator $dataGenerator)
    {
        $this->routeParser = $routeParser;
        $this->dataGenerator = $dataGenerator;
        $this->currentGroupPrefix = '';
    }
    public function addRoute($httpMethod, $route, $handler)
    {
        $route = $this->currentGroupPrefix . $route;
        $routeDatas = $this->routeParser->parse($route);
        foreach ((array) $httpMethod as $method) {
            foreach ($routeDatas as $routeData) {
                $this->dataGenerator->addRoute($method, $routeData, $handler);
            }
        }
    }
    public function addGroup($prefix, callable $callback)
    {
        $previousGroupPrefix = $this->currentGroupPrefix;
        $this->currentGroupPrefix = $previousGroupPrefix . $prefix;
        $callback($this);
        $this->currentGroupPrefix = $previousGroupPrefix;
    }
    public function get($route, $handler)
    {
        $this->addRoute('GET', $route, $handler);
    }
    public function post($route, $handler)
    {
        $this->addRoute('POST', $route, $handler);
    }
    public function put($route, $handler)
    {
        $this->addRoute('PUT', $route, $handler);
    }
    public function delete($route, $handler)
    {
        $this->addRoute('DELETE', $route, $handler);
    }
    public function patch($route, $handler)
    {
        $this->addRoute('PATCH', $route, $handler);
    }
    public function head($route, $handler)
    {
        $this->addRoute('HEAD', $route, $handler);
    }
    public function getData()
    {
        return $this->dataGenerator->getData();
    }
}
}

namespace FastRoute {
class Route
{
    public $httpMethod;
    public $regex;
    public $variables;
    public $handler;
    public function __construct($httpMethod, $handler, $regex, $variables)
    {
        $this->httpMethod = $httpMethod;
        $this->handler = $handler;
        $this->regex = $regex;
        $this->variables = $variables;
    }
    public function matches($str)
    {
        $regex = '~^' . $this->regex . '$~';
        return (bool) preg_match($regex, $str);
    }
}
}

namespace FastRoute {
interface DataGenerator
{
    public function addRoute($httpMethod, $routeData, $handler);
    public function getData();
}
}

namespace FastRoute {
interface RouteParser
{
    public function parse($route);
}
}

namespace FastRoute {
interface Dispatcher
{
    const NOT_FOUND = 0;
    const FOUND = 1;
    const METHOD_NOT_ALLOWED = 2;
    public function dispatch($httpMethod, $uri);
}
}

namespace FastRoute\Dispatcher {
use FastRoute\Dispatcher;
abstract class RegexBasedAbstract implements Dispatcher
{
    protected $staticRouteMap = [];
    protected $variableRouteData = [];
    abstract protected function dispatchVariableRoute($routeData, $uri);
    public function dispatch($httpMethod, $uri)
    {
        if (isset($this->staticRouteMap[$httpMethod][$uri])) {
            $handler = $this->staticRouteMap[$httpMethod][$uri];
            return [self::FOUND, $handler, []];
        }
        $varRouteData = $this->variableRouteData;
        if (isset($varRouteData[$httpMethod])) {
            $result = $this->dispatchVariableRoute($varRouteData[$httpMethod], $uri);
            if ($result[0] === self::FOUND) {
                return $result;
            }
        }
        if ($httpMethod === 'HEAD') {
            if (isset($this->staticRouteMap['GET'][$uri])) {
                $handler = $this->staticRouteMap['GET'][$uri];
                return [self::FOUND, $handler, []];
            }
            if (isset($varRouteData['GET'])) {
                $result = $this->dispatchVariableRoute($varRouteData['GET'], $uri);
                if ($result[0] === self::FOUND) {
                    return $result;
                }
            }
        }
        if (isset($this->staticRouteMap['*'][$uri])) {
            $handler = $this->staticRouteMap['*'][$uri];
            return [self::FOUND, $handler, []];
        }
        if (isset($varRouteData['*'])) {
            $result = $this->dispatchVariableRoute($varRouteData['*'], $uri);
            if ($result[0] === self::FOUND) {
                return $result;
            }
        }
        $allowedMethods = [];
        foreach ($this->staticRouteMap as $method => $uriMap) {
            if ($method !== $httpMethod && isset($uriMap[$uri])) {
                $allowedMethods[] = $method;
            }
        }
        foreach ($varRouteData as $method => $routeData) {
            if ($method === $httpMethod) {
                continue;
            }
            $result = $this->dispatchVariableRoute($routeData, $uri);
            if ($result[0] === self::FOUND) {
                $allowedMethods[] = $method;
            }
        }
        if ($allowedMethods) {
            return [self::METHOD_NOT_ALLOWED, $allowedMethods];
        }
        return [self::NOT_FOUND];
    }
}
}

namespace FastRoute\Dispatcher {
class MarkBased extends RegexBasedAbstract
{
    public function __construct($data)
    {
        list($this->staticRouteMap, $this->variableRouteData) = $data;
    }
    protected function dispatchVariableRoute($routeData, $uri)
    {
        foreach ($routeData as $data) {
            if (!preg_match($data['regex'], $uri, $matches)) {
                continue;
            }
            list($handler, $varNames) = $data['routeMap'][$matches['MARK']];
            $vars = [];
            $i = 0;
            foreach ($varNames as $varName) {
                $vars[$varName] = $matches[++$i];
            }
            return [self::FOUND, $handler, $vars];
        }
        return [self::NOT_FOUND];
    }
}
}

namespace FastRoute\Dispatcher {
class GroupPosBased extends RegexBasedAbstract
{
    public function __construct($data)
    {
        list($this->staticRouteMap, $this->variableRouteData) = $data;
    }
    protected function dispatchVariableRoute($routeData, $uri)
    {
        foreach ($routeData as $data) {
            if (!preg_match($data['regex'], $uri, $matches)) {
                continue;
            }
            for ($i = 1; '' === $matches[$i]; ++$i) {
            }
            list($handler, $varNames) = $data['routeMap'][$i];
            $vars = [];
            foreach ($varNames as $varName) {
                $vars[$varName] = $matches[$i++];
            }
            return [self::FOUND, $handler, $vars];
        }
        return [self::NOT_FOUND];
    }
}
}

namespace FastRoute\Dispatcher {
class GroupCountBased extends RegexBasedAbstract
{
    public function __construct($data)
    {
        list($this->staticRouteMap, $this->variableRouteData) = $data;
    }
    protected function dispatchVariableRoute($routeData, $uri)
    {
        foreach ($routeData as $data) {
            if (!preg_match($data['regex'], $uri, $matches)) {
                continue;
            }
            list($handler, $varNames) = $data['routeMap'][count($matches)];
            $vars = [];
            $i = 0;
            foreach ($varNames as $varName) {
                $vars[$varName] = $matches[++$i];
            }
            return [self::FOUND, $handler, $vars];
        }
        return [self::NOT_FOUND];
    }
}
}

namespace FastRoute\Dispatcher {
class CharCountBased extends RegexBasedAbstract
{
    public function __construct($data)
    {
        list($this->staticRouteMap, $this->variableRouteData) = $data;
    }
    protected function dispatchVariableRoute($routeData, $uri)
    {
        foreach ($routeData as $data) {
            if (!preg_match($data['regex'], $uri . $data['suffix'], $matches)) {
                continue;
            }
            list($handler, $varNames) = $data['routeMap'][end($matches)];
            $vars = [];
            $i = 0;
            foreach ($varNames as $varName) {
                $vars[$varName] = $matches[++$i];
            }
            return [self::FOUND, $handler, $vars];
        }
        return [self::NOT_FOUND];
    }
}
}

namespace FastRoute {
if (!function_exists('FastRoute\simpleDispatcher')) {
    function simpleDispatcher(callable $routeDefinitionCallback, array $options = [])
    {
        $options += ['routeParser' => 'FastRoute\RouteParser\Std', 'dataGenerator' => 'FastRoute\DataGenerator\GroupCountBased', 'dispatcher' => 'FastRoute\Dispatcher\GroupCountBased', 'routeCollector' => 'FastRoute\RouteCollector'];
        $routeCollector = new $options['routeCollector'](new $options['routeParser'](), new $options['dataGenerator']());
        $routeDefinitionCallback($routeCollector);
        return new $options['dispatcher']($routeCollector->getData());
    }
    function cachedDispatcher(callable $routeDefinitionCallback, array $options = [])
    {
        $options += ['routeParser' => 'FastRoute\RouteParser\Std', 'dataGenerator' => 'FastRoute\DataGenerator\GroupCountBased', 'dispatcher' => 'FastRoute\Dispatcher\GroupCountBased', 'routeCollector' => 'FastRoute\RouteCollector', 'cacheDisabled' => false];
        if (!isset($options['cacheFile'])) {
            throw new \LogicException('Must specify "cacheFile" option');
        }
        if (!$options['cacheDisabled'] && file_exists($options['cacheFile'])) {
            $dispatchData = require $options['cacheFile'];
            if (!is_array($dispatchData)) {
                throw new \RuntimeException('Invalid cache file "' . $options['cacheFile'] . '"');
            }
            return new $options['dispatcher']($dispatchData);
        }
        $routeCollector = new $options['routeCollector'](new $options['routeParser'](), new $options['dataGenerator']());
        $routeDefinitionCallback($routeCollector);
        $dispatchData = $routeCollector->getData();
        if (!$options['cacheDisabled']) {
            file_put_contents($options['cacheFile'], '<?php return ' . var_export($dispatchData, true) . ';');
        }
        return new $options['dispatcher']($dispatchData);
    }
}
}

