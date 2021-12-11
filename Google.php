<?php

namespace dokuwiki\plugin\oauthgoogle;

use OAuth\Common\Token\TokenInterface;

/**
 * Modify the default lusitania Google Service
 */
class Google extends \OAuth\OAuth2\Service\Google {

    /**
     * To make sure we get a refresh token, we need consent for an offline
     * application. Thuse we always ask for consent again on login.
     *
     * @link https://stackoverflow.com/a/10857806/172068
     * @inheritdoc
     */
    public function getAuthorizationEndpoint()
    {
        // offline mode provides a refresh token
        $this->setAccessType('offline');

        // always show consent screen again
        $uri = parent::getAuthorizationEndpoint();
        $uri->addToQuery('prompt', 'consent');
        return $uri;
    }

    /**
     * Google does not reissue refresh tokens on access token refresh
     *
     * @inheritdoc
     */
    public function refreshAccessToken(TokenInterface $token)
    {
        // remember old refresh token
        $refreshToken = $token->getRefreshToken();

        $token = parent::refreshAccessToken($token);

        // store the refresh token again
        if(!$token->getRefreshToken()) {
            $token->setRefreshToken($refreshToken);
            $this->storage->storeAccessToken($this->service(), $token);
        }

        return $token;
    }

}
