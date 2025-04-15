<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class propertyImages extends Model
{
    protected $table = 'property_images';
    public $timestamps = true;

    protected $fillable = [
        'property_id',
        'image_path',
        'public_id',
        'caption',
        'is_featured',

    ];

    // One-to-one (inverse): propertyImages belongs to one Properties
    public function property()
    {
        return $this->belongsTo(Properties::class, 'property_id', 'id');
    }
}
