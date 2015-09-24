<?php

namespace Mdanter\X509\Certificates;

use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\X509\EcDomain;

class Csr
{
    /**
     * @var NamedCurveFp
     */
    private $curve;

    /**
     * @var PublicKeyInterface
     */
    private $publicKey;

    /**
     * @var string
     */
    private $sigAlgorithm;

    /**
     * @var SignatureInterface
     */
    private $signature;

    /**
     * @var CertificateSubject
     */
    private $subject;

    /**
     * @param EcDomain $domain
     * @param CertificateSubject $subject
     * @param $sigAlgorithm
     * @param NamedCurveFp $curve
     * @param PublicKeyInterface $publicKey
     * @param SignatureInterface $signature
     */
    public function __construct(EcDomain $domain, CertificateSubject $subject, PublicKeyInterface $publicKey, SignatureInterface $signature)
    {
        $this->sigAlgorithm = $domain->getSigAlgorithm();
        $this->curve = $domain->getCurve();
        $this->publicKey = $publicKey;
        $this->signature = $signature;
        $this->subject = $subject;
    }

    /**
     * @return PublicKeyInterface
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * @return SignatureInterface
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @return string
     */
    public function getSigAlgorithm()
    {
        return $this->sigAlgorithm;
    }

    /**
     * @return NamedCurveFp
     */
    public function getCurve()
    {
        return $this->curve;
    }

    /**
     * @return CertificateSubject
     */
    public function getSubject()
    {
        return $this->subject;
    }
}
