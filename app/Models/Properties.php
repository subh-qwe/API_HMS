<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Properties extends Model
{
    protected $table = 'properties';
    protected $fillable = [
        'host_id',
        'title',
        'description',
        'property_type',
        'address',
        'city',
        'state',
        'zip_code',
        'latitude',
        'longitude',
        'bedrooms',
        'bathrooms',
        'max_guests',
        'price_per_night',
        'cleaning_fee',
        'service_fee',
        'status'
    ];
    public $timestamps = true;

    public function images()
    {
        return $this->hasMany(PropertyImages::class, 'property_id', 'id');
    }

    public function amenities()
    {
        return $this->belongsToMany(Amenity::class, 'property_amenity', 'property_id', 'amenity_id');
    }
}
