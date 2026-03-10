<?php

namespace Lineage\DTO;

use Lineage\Functions\KeyHelpers;

class DruidInfoDTO
{
    public function __construct(
        private array $expectations,
        private ?string $druid = null,
        private ?int $participants = 2
    ) {
        $this->druid = $druid ?? KeyHelpers::generateDRUID();
    }

    public function formatForAPI(): array
    {
        return [
            'participants' => $this->participants,
            'druid' => $this->druid,
            'expectations' => $this->expectations,
        ];
    }

    public function getDruid(): string
    {
        return $this->druid;
    }
}
