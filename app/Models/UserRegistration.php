<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class UserRegistration extends Model
{
   protected $table = 'users';
   protected $fillable = ['name', 'email', 'password', 'phone_number', 'profile_image', 'role','remember_token','otp'];

   public $timestamps = true;
}
