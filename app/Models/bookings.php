<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class bookings extends Model
{
    protected $table = 'bookings';
    protected $timestamps = true;


    protected $fillable = [

        'check_in_date',
        'check_out_date',
        'guests_count',
        
        'total_price',
        'status',
    ];
}
