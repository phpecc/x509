<?php

namespace Mdanter\X509\Serializer\Certificates\Certificate;

use FG\ASN1\Universal\BitString;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\ObjectIdentifier;
use FG\ASN1\Universal\Sequence;
use FG\ASN1\Universal\UTCTime;
use Mdanter\X509\Certificates\Certificate;
use Mdanter\X509\Certificates\CertificateInfo;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Curves\NamedCurveFp;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Serializer\Util\CurveOidMapper;
use Mdanter\X509\Serializer\Certificates\CertificateSerializer;
use Mdanter\X509\Serializer\Certificates\CertificateSubjectSerializer;
use Mdanter\X509\Serializer\Certificates\Extensions\AbstractExtensions;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\X509\Serializer\Signature\DerSignatureSerializer;
use Mdanter\X509\Serializer\Util\SigAlgorithmOidMapper;

class Formatter
{
    private $extension;

    /**
     * @var CertificateSubjectSerializer
     */
    private $subjectSer;

    /**
     * @var DerPublicKeySerializer
     */
    private $pubKeySer;

    /**
     * @var DerSignatureSerializer
     */
    private $sigSer;

    /**
     * @param CertificateSubjectSerializer $csrSubSerializer
     * @param DerPublicKeySerializer $publicKeySerializer
     * @param DerSignatureSerializer $sigSer
     * @param AbstractExtensions|null $extension
     */
    public function __construct(CertificateSubjectSerializer $csrSubSerializer, DerPublicKeySerializer $publicKeySerializer, DerSignatureSerializer $sigSer, AbstractExtensions $extension = null)
    {
        $this->subjectSer = $csrSubSerializer;
        $this->pubKeySer = $publicKeySerializer;
        $this->sigSer = $sigSer;
        $this->extension = $extension;
    }

    /**
     * @param NamedCurveFp $curve
     * @param PublicKeyInterface $publicKey
     * @return Sequence
     */
    public function getSubjectKeyASN(NamedCurveFp $curve, PublicKeyInterface $publicKey)
    {
        return new Sequence(
            new Sequence(
                new ObjectIdentifier(CertificateSerializer::ECPUBKEY_OID),
                CurveOidMapper::getCurveOid($curve)
            ),
            new BitString($this->pubKeySer->getUncompressedKey($publicKey))
        );
    }

    /**
     * @param CertificateInfo $info
     * @return Sequence
     */
    public function getCertInfoAsn(CertificateInfo $info)
    {
        $curve = EccFactory::getSecgCurves()->curve256k1();
        if ($this->extension === null) {
            return new Sequence(
                //new Integer($info->getVersion()),
                new Integer($info->getSerialNo()),
                new Sequence(
                    SigAlgorithmOidMapper::getSigAlgorithmOid($info->getSigAlgorithm())
                ),
                $this->subjectSer->toAsn($info->getIssuerInfo()),
                new Sequence(
                    new UTCTime($info->getValidityStart()->format(CertificateSerializer::UTCTIME_FORMAT)),
                    new UTCTime($info->getValidityEnd()->format(CertificateSerializer::UTCTIME_FORMAT))
                ),
                $this->subjectSer->toAsn($info->getSubjectInfo()),
                $this->getSubjectKeyASN($curve, $info->getPublicKey())
            );
        }

        return new Sequence(
            //new Integer($info->getVersion()),
            new Integer($info->getSerialNo()),
            new Sequence(
                SigAlgorithmOidMapper::getSigAlgorithmOid($info->getSigAlgorithm())
            ),
            $this->subjectSer->toAsn($info->getIssuerInfo()),
            new Sequence(
                new UTCTime($info->getValidityStart()->format(CertificateSerializer::UTCTIME_FORMAT)),
                new UTCTime($info->getValidityEnd()->format(CertificateSerializer::UTCTIME_FORMAT))
            ),
            $this->subjectSer->toAsn($info->getSubjectInfo()),
            $this->getSubjectKeyASN($curve, $info->getPublicKey()),
            $this->extension->apply($info)
        );
    }

    /**
     * @param Certificate $cert
     * @return Sequence
     */
    public function getCertificateASN(Certificate $cert)
    {
        return new Sequence(
            $this->getCertInfoASN($cert->getInfo()),
            new Sequence(
                SigAlgorithmOidMapper::getSigAlgorithmOid($cert->getSigAlgorithm())
            ),
            new BitString(bin2hex($this->sigSer->serialize($cert->getSignature())))
        );
    }
}
