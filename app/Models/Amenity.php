<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Amenity extends Model
{
    protected $table = 'amenities';


    public $timestamps = true;


    protected $fillable = [
        'name',
        'icon',
    ];


    // Many-to-many relationship with Property
    public function properties()
    {
        return $this->belongsToMany(Properties::class, 'property_amenity', 'amenity_id', 'property_id');
    }


}
