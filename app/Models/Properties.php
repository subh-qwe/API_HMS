<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Properties extends Model
{
    protected $table = 'properties';
    protected $fillable = [
        'title',
        'description',
        'property_type',
        'address',
        'city',
        'state',
        'zip_code',
        'bedrooms',
        'bathrooms',
        'max_guests',
        'price_per_night',
        'cleaning_fee',
        'service_fee',
        'status'
    ];
}
