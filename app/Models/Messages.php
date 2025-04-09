<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Messages extends Model
{
    protected $table = 'messages';
    protected $timestamps = true;

    protected $fillable = [
        'sender_id',
        'recipient_id',
        'property_id',
        'booking_id',
        'message',
        'read_at',
    ];
}
