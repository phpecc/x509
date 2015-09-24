<?php

namespace Mdanter\X509\Extensions;

class MultiValuedExtension
{
    /**
     * @var bool
     */
    private $critical;

    /**
     * @var array
     */
    protected $values;

    /**
     * @param null|bool $critical
     */
    public function __construct($critical)
    {
        if (!is_null($critical) && !is_bool($critical)) {
            throw new \InvalidArgumentException('MultiValuedExtension: critical not null or bool');
        }

        $this->critical = $critical;
    }

    /**
     * @return bool
     */
    public function isCritical()
    {
        return $this->critical;
    }

    /**
     * @return array
     */
    public function getValues()
    {
        return $this->values;
    }
}
