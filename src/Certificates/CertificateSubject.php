<?php

namespace Mdanter\X509\Certificates;

class CertificateSubject
{
    /**
     * @var array
     */
    private $values = [];

    /**
     * @param array $subjectDetails
     */
    public function __construct(array $subjectDetails)
    {
        $this->values = $subjectDetails;
    }

    /**
     * @return array
     */
    public function getValues()
    {
        return $this->values;
    }

    /**
     * @param string $key
     * @return null
     */
    public function value($key)
    {
        if (isset($this->values[$key])) {
            return $this->values[$key];
        }

        return null;
    }
}
