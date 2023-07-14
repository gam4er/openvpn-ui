package controllers

import (
	"html/template"

	"github.com/d3vilh/openvpn-ui/state"

	"github.com/beego/beego"
	"github.com/beego/beego/orm"
	"github.com/d3vilh/openvpn-ui/models"
)

type SettingsController struct {
	BaseController
}

func (c *SettingsController) NestPrepare() {
	if !c.IsLogin {
		c.Ctx.Redirect(302, c.LoginPath())
		return
	}
	c.Data["breadcrumbs"] = &BreadCrumbs{
		Title: "Settings",
	}
}

func (c *SettingsController) Get() {
	c.TplName = "settings.html"
	c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	settings := models.Settings{Profile: "default"}
	_ = settings.Read("Profile")
	c.Data["Settings"] = &settings
}

func (c *SettingsController) Post() {
	c.TplName = "settings.html"

	flash := beego.NewFlash()
	settings := models.Settings{Profile: "default"}
	_ = settings.Read("Profile")
	if err := c.ParseForm(&settings); err != nil {
		beego.Warning(err)
		flash.Error(err.Error())
		flash.Store(&c.Controller)
		return
	}
	c.Data["Settings"] = &settings

	o := orm.NewOrm()
	if _, err := o.Update(&settings); err != nil {
		flash.Error(err.Error())
	} else {
		flash.Success("Settings has been updated")
		state.GlobalCfg = settings
	}
	flash.Store(&c.Controller)
}
