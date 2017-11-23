{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Servant.Auth.Server.Internal where

import           Control.Monad.Trans (liftIO)
import           Servant             ((:>), Handler, HasServer (..),
                                      Proxy (..),
                                      HasContextEntry(getContextEntry))
import           Servant.Auth

import Servant.Auth.Server.Internal.AddSetCookie
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Types

import Servant.Server.Internal.RoutingApplication

instance ( n ~ 'S ('S 'Z)
         , HasServer (AddSetCookiesApi n api) ctxs, AreAuths auths ctxs v
         , AddSetCookies n (ServerT api Handler) (ServerT (AddSetCookiesApi n api) Handler)
         , ToJWT v
         , HasContextEntry ctxs CookieSettings
         , HasContextEntry ctxs JWTSettings
         ) => HasServer (Auth auths v :> api) ctxs where
  type ServerT (Auth auths v :> api) m = AuthResult v -> ServerT api m

  route _ context subserver =
    route (Proxy :: Proxy (AddSetCookiesApi n api))
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (AuthResult v, SetCookieList ('S ('S 'Z)))
      authCheck = withRequest $ \req -> liftIO $ do
        authResult <- runAuthCheck (runAuths (Proxy :: Proxy auths) context) req
        cookies <- makeCookies authResult
        return (authResult, cookies)

      jwtSettings :: JWTSettings
      jwtSettings = getContextEntry context

      cookieSettings :: CookieSettings
      cookieSettings = getContextEntry context

      makeCookies :: AuthResult v -> IO (SetCookieList ('S ('S 'Z)))
      makeCookies authResult = do
        -- FIXME: This probably breaks unauthenticated XSRF
        --        causing extra 401 errors :(
        --        I didn't check, though.
        --        Every time you reset the xsrf token, there is
        --        potential for a race condition in the browser,
        --        because the response may arrive between the
        --        time the cookie was read and the time the next
        --        request gets sent with the new cookie. This
        --        race condition is highly problematic when concurrent
        --        requests are being sent from the browser.
        -- Used to be: csrf <- makeXsrfCookie cookieSettings
        let csrf = noXsrfTokenCookie cookieSettings
        fmap (Just csrf `SetCookieCons`) $
          case authResult of
            (Authenticated v) -> do
              ejwt <- makeSessionCookie cookieSettings jwtSettings v
              case ejwt of
                Nothing  -> return $ Nothing `SetCookieCons` SetCookieNil
                Just jwt -> return $ Just jwt `SetCookieCons` SetCookieNil
            _ -> return $ Nothing `SetCookieCons` SetCookieNil

      go :: ( old ~ ServerT api Handler
            , new ~ ServerT (AddSetCookiesApi n api) Handler
            )
         => (AuthResult v -> ServerT api Handler)
         -> (AuthResult v, SetCookieList n) -> new
      go fn (authResult, cookies) = addSetCookies cookies $ fn authResult
