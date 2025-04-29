<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class bookings extends Model
{
    protected $table = 'bookings';
    public $timestamps = true;


    protected $fillable = [
        'property_id',
        'guest_id',
        'check_in_date',
        'check_out_date',
        'guests_count',
        'total_price',
        'status',
    ];

    public function property(){
        return $this->belongsTo(Properties::class,'property_id','id');
    }

    public function guest(){
        return $this->belongsTo(UserRegistration::class,'guest_id','id');
    }

    public function reviews(){
        return $this->hasMany(propertyReview::class, 'booking_id','id');
    }


}
