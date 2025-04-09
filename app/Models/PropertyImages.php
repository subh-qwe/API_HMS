<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class propertyImages extends Model
{
    protected $table = 'property_images';
    protected $timestamps = true;

    protected $fillable = [
        'property_id',
        'image_path',
        'caption',
        'is_featured',

    ];
}
