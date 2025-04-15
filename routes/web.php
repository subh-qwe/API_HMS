<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$router->post('/auth/login', 'LoginController@login');


$router->get('/', function () use ($router) {
    echo('HMS API is Running 🐱‍🏍🐱‍🏍🐱‍🏍');
});

$router->get('/version', function () use ($router) {
   
    return $router->app->version();
});

//USER MANAGEMENT 
// 1 Create user or Signup 
 $router->post('website/user/signup', 'AuthController@signup');
 $router->post('website/user/verifyotp','AuthController@verifyOtp');

// Property Management
// 1 Create Property
$router->post('user/property/addnewproperty', 'PropertyController@store');
