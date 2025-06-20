<?php

/** @var \Laravel\Lumen\Routing\Router $router */

use GuzzleHttp\Middleware;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PropertyController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\BookingController;
use App\Http\Controllers\ReviewController;




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

//ADMIN MANAGEMENT

//In the middleware, we check if the user is authenticated and if the user has the admin role
$router->group(['middleware' => ['auth', 'admin.role']], function () use ($router) {
    $router->get('/admin/dashboard', 'AdminController@adminActions');
    $router->get('/admin/unavailableproperties','AdminController@getUnavailableProperties');
    $router->get('/admin/getallstats','AdminController@getAllStats');
    $router->get('admin/getbookings','AdminController@getBookings');
    $router->get('admin/getusers','AdminController@getAllUsers');
    $router->post('admin/updatestatus','AdminController@UpdatePropertyStatus');
    $router->post('admin/rejectproperty','AdminController@rejectProperties');

});


//USER MANAGEMENT 
// 1 Create user or Signup 

 $router->post('website/user/signup', 'AuthController@signup');
 $router->post('website/user/verifyotp','AuthController@verifyOtp');
 $router->post('/website/user/login','AuthController@login');
 

// Property Management

$router->group(['prefix'=> 'property'], function () use ($router){
    $router->get('getproperties', 'PropertyController@listProperties');
    $router->get('getpropertybyid/{id}', 'PropertyController@getPropertybyId');
    $router->post('addnewproperty', 'PropertyController@store');
    $router->post('updateproperty/{id}', 'PropertyController@updateProperty');
    $router->post('deleteproperty/{id}', 'PropertyController@deleteProperty');
});



// 3 Property Booking Management
$router->post('user/property/bookproperty', ['middleware' => 'auth', 'uses' => 'BookingController@bookProperty']);
$router->post('user/property/cancelbooking', ['middleware' => 'auth', 'uses' => 'BookingController@cancelBooking']);



// Property Review Management
$router->post('user/property/reviewproperty', ['middleware' => 'auth', 'uses' => 'ReviewController@reviewProperty']);





// ************************ Example Usage of protected routes *******************
 //$router->group(['middleware' => 'jwt.auth'], function () use ($router) {
    //         $router->post('logout', 'AuthController@logout');
    //         $router->post('refresh', 'AuthController@refresh');
    //         $router->get('me', 'AuthController@me');
    //         // Your other protected routes...
    //     });
