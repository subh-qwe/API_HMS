<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class PropertyAvailability extends Model
{
    protected $table = 'availability';
    protected $timestamps = true;
    

    protected $fillable = [
        'date',
        'is_available',
        'special_price',
    ];

}
