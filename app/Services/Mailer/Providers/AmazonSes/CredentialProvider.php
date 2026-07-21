<?php

namespace FluentMail\App\Services\Mailer\Providers\AmazonSes;

/**
 * Resolves AWS credentials from the environment when the connection is
 * configured to use the IAM role attached to the server (EC2 instance
 * profile, Elastic Beanstalk, or ECS/Fargate task role) instead of a
 * stored access key pair.
 *
 * Resolution order (same as the official AWS SDK default chain):
 *   1. Environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
 *   2. ECS / Fargate container credentials endpoint
 *   3. EC2 instance metadata service (IMDSv2, falling back to IMDSv1)
 *
 * Temporary credentials are cached in memory for the current request only.
 * They are intentionally never persisted to the database or transients.
 */
class CredentialProvider
{
    const ECS_CREDENTIALS_HOST = 'http://169.254.170.2';

    const EC2_METADATA_HOST = 'http://169.254.169.254';

    const REQUEST_TIMEOUT = 2;

    /**
     * Seconds before the reported expiration when cached credentials
     * are considered stale and re-fetched.
     */
    const EXPIRATION_MARGIN = 300;

    private static $credentials = null;

    private static $error = null;

    /**
     * Get credentials from the server's IAM role or environment.
     *
     * @return array|\WP_Error ['access_key' => '', 'secret_key' => '', 'security_token' => '', 'expires' => int|null]
     */
    public static function get()
    {
        if (self::$credentials && !self::isExpired(self::$credentials)) {
            return self::$credentials;
        }

        // Avoid repeated metadata timeouts within the same request
        if (self::$error) {
            return self::$error;
        }

        $credentials = self::fromEnvironment();

        if (!$credentials) {
            $credentials = self::fromEcsMetadata();
        }

        if (!$credentials) {
            $credentials = self::fromEc2Metadata();
        }

        if (!$credentials) {
            self::$error = new \WP_Error(
                422,
                __('Could not retrieve AWS credentials from the environment. Please make sure this site is running on AWS (EC2, Elastic Beanstalk or ECS) and an IAM role with SES permissions is attached to the instance profile or task role.', 'fluent-smtp')
            );

            return self::$error;
        }

        self::$credentials = $credentials;

        return $credentials;
    }

    private static function isExpired($credentials)
    {
        if (empty($credentials['expires'])) {
            return false;
        }

        return $credentials['expires'] - self::EXPIRATION_MARGIN <= time();
    }

    private static function fromEnvironment()
    {
        $accessKey = getenv('AWS_ACCESS_KEY_ID');
        $secretKey = getenv('AWS_SECRET_ACCESS_KEY');

        if (!$accessKey || !$secretKey) {
            return null;
        }

        return [
            'access_key'     => $accessKey,
            'secret_key'     => $secretKey,
            'security_token' => getenv('AWS_SESSION_TOKEN') ?: '',
            'expires'        => null
        ];
    }

    /**
     * ECS / Fargate task role credentials.
     *
     * @see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
     */
    private static function fromEcsMetadata()
    {
        $relativeUri = getenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI');
        $fullUri = getenv('AWS_CONTAINER_CREDENTIALS_FULL_URI');

        if ($relativeUri) {
            $url = self::ECS_CREDENTIALS_HOST . $relativeUri;
        } elseif ($fullUri) {
            $url = $fullUri;
        } else {
            return null;
        }

        $headers = [];

        $authToken = getenv('AWS_CONTAINER_AUTHORIZATION_TOKEN');
        $authTokenFile = getenv('AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE');

        if (!$authToken && $authTokenFile && is_readable($authTokenFile)) {
            $authToken = trim((string)file_get_contents($authTokenFile));
        }

        if ($authToken) {
            $headers['Authorization'] = $authToken;
        }

        $body = self::request($url, 'GET', $headers);

        return self::parseCredentialsJson($body);
    }

    /**
     * EC2 instance profile credentials (also used by Elastic Beanstalk).
     *
     * @see https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
     */
    private static function fromEc2Metadata()
    {
        $headers = [];

        // IMDSv2: session token first. Falls back to IMDSv1 if unavailable.
        $imdsToken = self::request(
            self::EC2_METADATA_HOST . '/latest/api/token',
            'PUT',
            ['X-aws-ec2-metadata-token-ttl-seconds' => '21600']
        );

        if ($imdsToken) {
            $headers['X-aws-ec2-metadata-token'] = $imdsToken;
        }

        $credentialsPath = self::EC2_METADATA_HOST . '/latest/meta-data/iam/security-credentials/';

        $roleName = self::request($credentialsPath, 'GET', $headers);

        if (!$roleName) {
            return null;
        }

        $roleName = strtok(trim($roleName), "\n");

        $body = self::request($credentialsPath . $roleName, 'GET', $headers);

        return self::parseCredentialsJson($body);
    }

    private static function parseCredentialsJson($body)
    {
        if (!$body) {
            return null;
        }

        $data = json_decode($body, true);

        if (empty($data['AccessKeyId']) || empty($data['SecretAccessKey'])) {
            return null;
        }

        $expires = null;
        if (!empty($data['Expiration'])) {
            $expires = strtotime($data['Expiration']) ?: null;
        }

        return [
            'access_key'     => $data['AccessKeyId'],
            'secret_key'     => $data['SecretAccessKey'],
            'security_token' => isset($data['Token']) ? $data['Token'] : '',
            'expires'        => $expires
        ];
    }

    /**
     * Minimal HTTP request against the link-local metadata endpoints.
     * Uses wp_remote_request (not wp_safe_remote_request) on purpose:
     * the metadata services live on link-local IPs which the safe
     * variant rejects.
     *
     * @return string|null Response body, or null on any failure.
     */
    private static function request($url, $method = 'GET', $headers = [])
    {
        $response = wp_remote_request($url, [
            'method'      => $method,
            'timeout'     => self::REQUEST_TIMEOUT,
            'redirection' => 0,
            'headers'     => $headers
        ]);

        if (is_wp_error($response)) {
            return null;
        }

        if (wp_remote_retrieve_response_code($response) !== 200) {
            return null;
        }

        $body = wp_remote_retrieve_body($response);

        return $body === '' ? null : $body;
    }
}
