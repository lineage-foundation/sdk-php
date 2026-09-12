<?php
namespace Lineage\Tests;
use PHPUnit\Framework\TestCase;
abstract class VectorTestCase extends TestCase {
    protected function vector(string $name): array {
        return json_decode(file_get_contents(__DIR__.'/fixtures/'.$name.'.json'), true);
    }
}
