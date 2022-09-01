using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;


namespace SecuringWebApiUsingApiKey.Attributes
{
    // Decorator to specify attribute will only be used on classes, like controllers.

    [AttributeUsage(validOn: AttributeTargets.Class)]
    /// <summary>
    /// Custom attribute so any request routed to the attributed controller will be redirected to the below attribute
    /// </summary>
    // Attribute transforms class into a custom attribute.
    // IAsyncActionFilter allows custom attribute to intercept the call request, process it, and route it back to the controller.
    public class ApiKeyAttribute : Attribute, IAsyncActionFilter
    {
        private const string APIKEYNAME = "ApiKey";
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            // Checking the request headers collection object if it has a key with name ApiKey
            if (!context.HttpContext.Request.Headers.TryGetValue(APIKEYNAME, out var extractedApiKey))
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "API Key was not provided"
                };
                return;
            }
            // Use dependency injection and configuration extensions libraries of Microsoft to load settings file and real its value
            var appSettings = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
            var apiKey = appSettings.GetValue<string>(APIKEYNAME);
            if (!apiKey.Equals(extractedApiKey))
            {
                context.Result = new ContentResult()
                {
                    StatusCode = 401,
                    Content = "API Key is not valid"
                };
                return;
            }
            await next();
        }
    }
}
