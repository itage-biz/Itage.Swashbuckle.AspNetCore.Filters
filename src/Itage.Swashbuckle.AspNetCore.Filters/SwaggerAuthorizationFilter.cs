using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;

namespace Swashbuckle.AspNetCore.AuthorizationFilters
{
    /// <summary>
    /// Adds correct Bearer: token authorization in generated swagger
    /// </summary>
    [ExcludeFromCodeCoverage]
    // ReSharper disable once ClassNeverInstantiated.Global
    public sealed class SwaggerAuthorizationFilter<T> : IOperationFilter
        where T : Attribute
    {
        private readonly Func<IReadOnlyCollection<T>, IEnumerable<OpenApiSecurityRequirement>> _callback;

        /// <summary>
        /// Creates a new authorization folder
        /// </summary>
        /// <param name="callback"></param>
        public SwaggerAuthorizationFilter(
            Func<IReadOnlyCollection<T>, IEnumerable<OpenApiSecurityRequirement>> callback)
        {
            _callback = callback;
        }

        /// <inheritdoc />>
        public void Apply(OpenApiOperation operation, OperationFilterContext context)
        {
            // Skipping anonymous
            if (GetControllerAndActionAttributes<AllowAnonymousAttribute>(context).Any())
                return;

            var attributes = GetControllerAndActionAttributes<T>(context);
            // Skipping endpoints without any authorization attributes
            if (!attributes.Any())
            {
                return;
            }

            foreach (var requirement in _callback(attributes))
            {
                operation.Security.Add(requirement);
            }

            // Adding default Unauthorized/Forbidden responses
            if (!operation.Security.Any())
            {
                return;
            }

            if (!operation.Responses.ContainsKey("401"))
                operation.Responses.Add("401", new OpenApiResponse {Description = "Unauthorized"});
            if (!operation.Responses.ContainsKey("403"))
                operation.Responses.Add("403", new OpenApiResponse {Description = "Forbidden"});
        }

        private static IReadOnlyCollection<TAttribute> GetControllerAndActionAttributes<TAttribute>(
            OperationFilterContext context)
            where TAttribute : Attribute
        {
            var objList = new List<TAttribute>();
            objList.AddRange(context.MethodInfo.GetCustomAttributes<TAttribute>());

            if (context.MethodInfo.DeclaringType != null)
            {
                objList.AddRange(context.MethodInfo.DeclaringType.GetTypeInfo().GetCustomAttributes<TAttribute>());
            }

            return objList;
        }
    }
}