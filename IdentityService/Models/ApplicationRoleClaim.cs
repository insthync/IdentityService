using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityService.Models
{
    public class ApplicationRoleClaim : IdentityRoleClaim<string>
    {
        [MaxLength(36)]
        public override string RoleId { get => base.RoleId; set => base.RoleId = value; }
    }
}
