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

    public function bookings()
    {
        return $this->hasMany(bookings::class, 'property_id', 'id');
    }

    public function reviews()
    {
        return $this->hasMany(PropertyReview::class, 'property_id', 'id');
    }

     public function host()
    {
        return $this->belongsTo(UserRegistration::class, 'host_id', 'id');
    }

    public static function UpdatePropertyStatus($status , $id)
    { 
        return self::where('id', $id)->update(['status' => $status]);
    }
}
