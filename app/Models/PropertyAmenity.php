<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class PropertyAmenity extends Model
{
    protected $table = 'property_amenity';
    protected $primaryKey = 'property_id';
    protected $timestamps = false;

    public function property()
    {
        return $this->belongsTo(Properties::class, 'property_id', 'id');
    }

}
