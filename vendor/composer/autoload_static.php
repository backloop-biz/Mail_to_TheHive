<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit3c1bdc15bcf31cbf914472d572e58dfc
{
    public static $prefixLengthsPsr4 = array (
        'L' => 
        array (
            'League\\HTMLToMarkdown\\' => 22,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'League\\HTMLToMarkdown\\' => 
        array (
            0 => __DIR__ . '/..' . '/league/html-to-markdown/src',
        ),
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit3c1bdc15bcf31cbf914472d572e58dfc::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit3c1bdc15bcf31cbf914472d572e58dfc::$prefixDirsPsr4;

        }, null, ClassLoader::class);
    }
}
