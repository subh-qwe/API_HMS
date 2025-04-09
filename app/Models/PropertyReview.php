<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class propertyReview extends Model
{
   protected $table = 'reviews';
   protected $timestamps = true;

   protected $fillable = [
       'rating',
       'comment',
   ];
}
