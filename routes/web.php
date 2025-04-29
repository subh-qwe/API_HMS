<?php

/** @var \Laravel\Lumen\Routing\Router $router */

use GuzzleHttp\Middleware;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PropertyController;
use App\Http\Controllers\AuthController;



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
 $router->post('/website/user/login','AuthController@login');
 // ************************** Pending API Edit user information*******************



// 2 Property Management
$router->post('user/property/addnewproperty', 'PropertyController@store');
$router->get('property/listproperties', 'PropertyController@listProperties');
$router->get('property/listpropertybyid/{id}', 'PropertyController@getPropertybyId');
//*****************************Pending API Edit Property information*******************


// 3 Property Booking Management
$router->post('user/property/bookproperty', ['middleware' => 'auth', 'uses' => 'BookingController@bookProperty']);



// Property Review Management




// ************************ Example Usage of protected routes *******************
 //$router->group(['middleware' => 'jwt.auth'], function () use ($router) {
    //         $router->post('logout', 'AuthController@logout');
    //         $router->post('refresh', 'AuthController@refresh');
    //         $router->get('me', 'AuthController@me');
    //         // Your other protected routes...
    //     });
