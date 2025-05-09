<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class PropertyReview extends Model
{
   protected $table = 'reviews';
   public $timestamps = true;

   protected $fillable = [
        'booking_id',
        'property_id',
        'guest_id',
        'rating',
        'comment',
   ];

   public function booking(){
     return $this->belongsTo(bookings::class,'booking_id','id');
   }

   public function property(){
     return $this->belongsTo(Properties::class,'property_id','id');
   }

   public function guest(){
     return $this->belongsTo(UserRegistration::class,'guest_id','id');
   }
}
