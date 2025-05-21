<?php

namespace App\Models;

use Hash;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Laravel\Lumen\Auth\Authorizable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class UserRegistration extends Model implements AuthenticatableContract, AuthorizableContract, JWTSubject
{
   use Authenticatable, Authorizable;

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     */
    public function getJWTCustomClaims()
    {
        return [
            'role' => $this->role,
        ];
    }

   protected $table = 'users';
   protected $fillable = ['name', 'email', 'password', 'phone_number', 'profile_image', 'role','remember_token','otp'];

   public $timestamps = true;

    public function findUserByEmail($email)
        {
            return $this->where('email', $email)->first();
        }

    public function validPass($email, $password)
        {
            $user = $this->where('email', $email)->first();
            if (!$user) {
                return false;
            }
            
            return app('hash')->check($password, $user->password);
        }

    public function bookings(){
        return $this->hasMany(bookings::class,'guest_id','id');
    }
    
    public function reviews(){
        return $this->hasMany(PropertyReview::class,'guest_id','id');
    }
    
}
