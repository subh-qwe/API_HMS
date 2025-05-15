<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class PropertyRating extends Model
{
    use HasFactory;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'property_id',
        'average_rating',
        'review_count',
    ];

    /**
     * Get the property that owns the rating.
     */
    public function property()
    {
        return $this->belongsTo(Properties::class);
    }
}