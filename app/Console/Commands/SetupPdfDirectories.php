<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class SetupPdfDirectories extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'setup:pdf-directories';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create all required directories for PDF functionality';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $directories = [
            storage_path('app/invoices'),
            storage_path('fonts'),
            resource_path('views/emails'),
            base_path('config'),
        ];

        foreach ($directories as $dir) {
            if (!File::isDirectory($dir)) {
                $this->info("Creating directory: $dir");
                File::makeDirectory($dir, 0755, true);
            } else {
                $this->info("Directory already exists: $dir");
            }
        }

        $this->info('Directory setup complete!');

        // Check if composer packages are installed
        if (!File::isDirectory(base_path('vendor/barryvdh/laravel-dompdf'))) {
            $this->warn('WARNING: laravel-dompdf package not found!');
            $this->warn('Please run: composer require barryvdh/laravel-dompdf');
        }

        // Reminder about permissions
        $this->info('');
        $this->info('Reminder: Make sure your web server has write permissions to these directories:');
        $this->info('- storage/app/invoices');
        $this->info('- storage/fonts');
        $this->info('- bootstrap/cache');
        $this->info('');

        $this->info('On Unix/Linux systems, you can use:');
        $this->info('chmod -R 775 storage');
        $this->info('chmod -R 775 bootstrap/cache');
        $this->info('chown -R www-data:www-data storage bootstrap/cache');

        return 0;
    }
}