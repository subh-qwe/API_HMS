<?php

if (!function_exists('public_path')) {
    /**
     * Get the path to the public folder.
     *
     * @param  string  $path
     * @return string
     */
    function public_path($path = '')
    {
        return app()->basePath('public') . ($path ? DIRECTORY_SEPARATOR . $path : '');
    }
}

if (!function_exists('url')) {
    /**
     * Generate a URL for the application.
     *
     * @param  string  $path
     * @param  mixed  $parameters
     * @param  bool  $secure
     * @return string
     */
    function url($path = null, $parameters = [], $secure = null)
    {
        $root = app('url')->to('/');
        if ($path) {
            return rtrim($root, '/') . '/' . ltrim($path, '/');
        }
        return $root;
    }
}

if (!function_exists('app_path')) {
    /**
     * Get the path to the app folder.
     *
     * @param  string  $path
     * @return string
     */
    function app_path($path = '')
    {
        return app()->basePath('app') . ($path ? DIRECTORY_SEPARATOR . $path : '');
    }
}
