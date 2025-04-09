<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    protected $table = 'invoices';


    public $timestamps = true;


    protected $fillable = [
        'booking_id',
        'invoice_number',
        'subtotal',
        'cleaning_fee',
        'service_fee',
        'total',
        'status',
    ];
}
