using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Threading.Tasks;
using System.Security.Claims;

namespace WebApiBearerTokenApp.OAuth
{
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // OAuthAuthorizationServerProvider sınıfının client erişimine izin verebilmek için ilgili ValidateClientAuthentication metotunu override ediyoruz.
            context.Validated();
        }

        // OAuthAuthorizationServerProvider sınıfının kaynak erişimine izin verebilmek için ilgili GrantResourceOwnerCredentials metotunu override ediyoruz.
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            // CORS ayarlarını set ediyoruz. -- Cross Domain yazım dan konu ile alakalı detaylı bilgi alabilirsiniz.
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            //validation işlemlerini ve kontrollerini bu kısımda yapıyoruz , örnek olması için sabit değerler verildi ,
            //bu kısmı db den okuyacak şekilde bir yapı kurgulanabilir.
            if (context.UserName.Equals("salihseker", StringComparison.OrdinalIgnoreCase) && context.Password == "123456")
            {
                //eğer başarılı ise ClaimsIdentity (Kimlik oluşturuyoruz)
                var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                identity.AddClaim(new Claim("sub", context.UserName));//Identity özelliklerini ekliyoruz.
                identity.AddClaim(new Claim("role", "admin"));

                context.Validated(identity);//Doğrulanmış olan kimliği context e ekliyoruz.
            }
            else
            {
                //eğer hata var ise bir hata mesajı gönderiyoruz. hata ve açıklaması şeklinde.
                context.SetError("Oturum Hatası", "Kullanıcı adı ve şifre hatalıdır");
            }
        }
    }
}