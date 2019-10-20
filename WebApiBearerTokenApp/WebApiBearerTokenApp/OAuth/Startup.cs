using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.OAuth;
using System.Web.Http;

[assembly: OwinStartup(typeof(WebApiBearerTokenApp.OAuth.Startup))]

namespace WebApiBearerTokenApp.OAuth
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration configuration = new HttpConfiguration();
            Configure(app);

            WebApiConfig.Register(configuration);
            app.UseWebApi(configuration);
        }

        private void Configure(IAppBuilder app)
        {
            OAuthAuthorizationServerOptions options = new OAuthAuthorizationServerOptions()
            {
                TokenEndpointPath = new Microsoft.Owin.PathString("/token"),// token alacağımız path'i belirtiyoruz
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(1),//token expire süresini ayarlıyoruz Örn : 1 saat
                AllowInsecureHttp = true,
                Provider = new AuthorizationServerProvider()
            };

            app.UseOAuthAuthorizationServer(options); //IAppBuilder e hazırlamış olduğumzu  Authorization ayarlarımızı veriyoruz.
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());// Authentication type olarak Bearer Authentication'ı kullanacağımızı belirtiyoruz.
        }
    }
}
