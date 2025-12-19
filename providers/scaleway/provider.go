package scaleway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/docker/go-units"
	"github.com/rs/zerolog/log"
	"github.com/scaleway/scaleway-sdk-go/api/block/v1"
	"github.com/scaleway/scaleway-sdk-go/api/instance/v1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/urfave/cli/v3"

	"go.woodpecker-ci.org/autoscaler/config"
	"go.woodpecker-ci.org/autoscaler/engine"
	"go.woodpecker-ci.org/woodpecker/v3/woodpecker-go/woodpecker"
)

var (
	ErrInvalidZone        = errors.New("invalid zone")
	ErrInvalidRegion      = errors.New("invalid region")
	ErrParameterNotSet    = errors.New("required parameter not set")
	ErrRegionOrZoneNotSet = errors.New("region or zone not set")
)

type Provider struct {
	secretKey        string
	accessKey        string
	defaultProjectID string
	zones            []scw.Zone
	region           *scw.Region
	projectID        *string
	prefix           string
	tags             []string
	commercialType   string
	image            string
	enableIPv6       bool
	enableIPv4       bool
	storage          scw.Size
	storageType      instance.VolumeVolumeType
	config           *config.Config
	client           *scw.Client
}

func New(_ context.Context, c *cli.Command, config *config.Config) (engine.Provider, error) {
	if !c.IsSet("scaleway-instance-type") {
		return nil, fmt.Errorf("%w: scaleway-instance-type", ErrParameterNotSet)
	}

	if !c.IsSet("scaleway-tags") {
		return nil, fmt.Errorf("%w: scaleway-tags", ErrParameterNotSet)
	}

	if !c.IsSet("scaleway-project") {
		return nil, fmt.Errorf("%w: scaleway-project", ErrParameterNotSet)
	}

	if !c.IsSet("scaleway-secret-key") {
		return nil, fmt.Errorf("%w: scaleway-secret-key", ErrParameterNotSet)
	}

	if !c.IsSet("scaleway-access-key") {
		return nil, fmt.Errorf("%w: scaleway-access-key", ErrParameterNotSet)
	}

	if !c.IsSet("scaleway-enable-ipv4") && !c.IsSet("scaleway-enable-ipv6") {
		return nil, fmt.Errorf("%w: scaleway-enable-ipv4, scaleway-enable-ipv6", ErrParameterNotSet)
	}

	p := &Provider{
		secretKey:        c.String("scaleway-secret-key"),
		accessKey:        c.String("scaleway-access-key"),
		defaultProjectID: c.String("scaleway-project"),
		projectID:        scw.StringPtr(c.String("scaleway-project")),
		prefix:           c.String("scaleway-prefix"),
		tags:             c.StringSlice("scaleway-tags"),
		commercialType:   c.String("scaleway-instance-type"),
		image:            c.String("scaleway-image"),
		enableIPv4:       c.Bool("scaleway-enable-ipv4"),
		enableIPv6:       c.Bool("scaleway-enable-ipv6"),
		storage:          scw.Size(c.Uint64("scaleway-storage-size") * units.GB),
		storageType:      instance.VolumeVolumeType(c.String("scaleway-storage-type")),
		config:           config,
	}

	zone := scw.Zone(c.String("scaleway-zone"))
	if !zone.Exists() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidZone, zone.String())
	}
	p.zones = []scw.Zone{zone}

	var err error
	p.client, err = scw.NewClient(scw.WithDefaultProjectID(p.defaultProjectID), scw.WithAuth(p.accessKey, p.secretKey))

	return p, err
}

func (p *Provider) DeployAgent(ctx context.Context, agent *woodpecker.Agent) error {
	_, err := p.getInstance(ctx, agent.Name)
	if err != nil {
		return err
	}

	inst, err := p.createInstance(ctx, agent)
	if err != nil {
		return err
	}

	err = p.setCloudInit(ctx, agent, inst)
	if err != nil {
		return err
	}

	// NB(raskyld): use the value for logging purpose once we implement slog
	_, err = p.bootInstance(ctx, inst)
	return err
}

func (p *Provider) RemoveAgent(ctx context.Context, agent *woodpecker.Agent) error {
	inst, err := p.getInstance(ctx, agent.Name)
	if err != nil {
		return err
	}

	return p.deleteInstance(ctx, inst)
}

func (p *Provider) ListDeployedAgentNames(ctx context.Context) ([]string, error) {
	instances, err := p.getAllInstances(ctx)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(instances))
	for _, inst := range instances {
		names = append(names, inst.Name)
	}

	return names, nil
}

func (p *Provider) getInstance(ctx context.Context, name string) (*instance.Server, error) {
	if err := p.resolveZones(); err != nil {
		return nil, err
	}

	api := instance.NewAPI(p.client)
	project := p.projectID

	if project == nil {
		project = &p.defaultProjectID
	}

	for _, zone := range p.zones {
		req := instance.ListServersRequest{
			Zone:    zone,
			Project: project,
			Name:    scw.StringPtr(name),
			Tags:    p.tags,
		}

		resp, err := api.ListServers(&req, scw.WithContext(ctx))
		if err != nil {
			return nil, err
		}

		if resp.TotalCount > 0 {
			if resp.TotalCount > 1 {
				log.Warn().Msg("found multiple instances with the same name, this may indicate orphaned resources")
			}
			return resp.Servers[0], nil
		}
	}

	return nil, nil
}

func (p *Provider) getAllInstances(ctx context.Context) ([]*instance.Server, error) {
	if err := p.resolveZones(); err != nil {
		return nil, err
	}

	api := instance.NewAPI(p.client)
	instances := make([]*instance.Server, 0)

	for _, zone := range p.zones {
		req := instance.ListServersRequest{
			Zone:    zone,
			Project: p.projectID,
			Tags:    p.tags,
			PerPage: scw.Uint32Ptr(100), //nolint:mnd
		}

		resp, err := api.ListServers(&req, scw.WithContext(ctx), scw.WithAllPages())
		if err != nil {
			return nil, err
		}

		if resp.TotalCount > 0 {
			instances = append(instances, resp.Servers...)
		}
	}

	return instances, nil
}

func (p *Provider) createIP(ctx context.Context, zone scw.Zone, ipType instance.IPType) (string, error) {
	api := instance.NewAPI(p.client)

	ipRequest := instance.CreateIPRequest{
		Zone:    zone,
		Project: p.projectID,
		Tags:    p.tags,
		Type:    ipType,
	}

	ip, err := api.CreateIP(&ipRequest, scw.WithContext(ctx))
	if err != nil {
		return "", err
	}

	return ip.IP.ID, nil
}

func combineErrors(collectedErrs error, newError error) error {
	if newError != nil {
		if collectedErrs == nil {
			collectedErrs = newError
		} else {
			collectedErrs = fmt.Errorf("%w; %w", collectedErrs, newError)
		}
	}

	return collectedErrs
}

func (p *Provider) deleteIP(ctx context.Context, zone scw.Zone, ipID string) error {
	api := instance.NewAPI(p.client)
	req := instance.DeleteIPRequest{
		Zone: zone,
		IP:   ipID,
	}
	return api.DeleteIP(&req, scw.WithContext(ctx))
}

func (p *Provider) deleteVolume(ctx context.Context, zone scw.Zone, volumeID string) error {
	api := block.NewAPI(p.client)
	req := block.DeleteVolumeRequest{
		Zone:     zone,
		VolumeID: volumeID,
	}
	return api.DeleteVolume(&req, scw.WithContext(ctx))
}

func (p *Provider) createInstance(ctx context.Context, agent *woodpecker.Agent) (*instance.Server, error) {
	if err := p.resolveZones(); err != nil {
		return nil, err
	}

	// TODO(raskyld): Implement a well-balanced zone anti-affinity to spread instance
	// 								evenly among zones for greater resilience.
	random := rand.New(rand.NewSource(time.Now().Unix()))
	zone := p.zones[random.Intn(len(p.zones))]

	api := instance.NewAPI(p.client)

	const maxIPCount = 2
	ipIDs := make([]string, 0, maxIPCount)

	if p.enableIPv4 {
		ip, err := p.createIP(ctx, zone, instance.IPTypeRoutedIPv4)
		if err != nil {
			return nil, err
		}

		ipIDs = append(ipIDs, ip)
	}

	if p.enableIPv6 {
		ip, err := p.createIP(ctx, zone, instance.IPTypeRoutedIPv6)
		if err != nil {
			for _, ipID := range ipIDs {
				cleanupErr := p.deleteIP(ctx, zone, ipID)
				err = combineErrors(err, cleanupErr)
			}
			return nil, err
		}

		ipIDs = append(ipIDs, ip)
	}

	req := instance.CreateServerRequest{
		Zone:              zone,
		Name:              agent.Name,
		DynamicIPRequired: scw.BoolPtr(false),
		CommercialType:    p.commercialType,
		Image:             scw.StringPtr(p.image),
		Volumes: map[string]*instance.VolumeServerTemplate{
			"0": {
				Boot:       scw.BoolPtr(true),
				Size:       scw.SizePtr(p.storage),
				VolumeType: p.storageType,
			},
		},
		PublicIPs: scw.StringsPtr(ipIDs),
		Project:   p.projectID,
		Tags:      p.tags,
	}

	res, err := api.CreateServer(&req, scw.WithContext(ctx))
	if err != nil {
		for _, ipID := range ipIDs {
			cleanupErr := p.deleteIP(ctx, zone, ipID)
			err = combineErrors(err, cleanupErr)
		}

		return nil, err
	}

	return res.Server, nil
}

func (p *Provider) setCloudInit(ctx context.Context, agent *woodpecker.Agent, inst *instance.Server) error {
	ud, err := engine.RenderUserDataTemplate(p.config, agent, nil)
	if err != nil {
		return err
	}

	api := instance.NewAPI(p.client)

	req := instance.SetServerUserDataRequest{
		Zone:     inst.Zone,
		ServerID: inst.ID,
		Key:      "cloud-init",
		Content:  bytes.NewBufferString(ud),
	}

	err = api.SetServerUserData(&req, scw.WithContext(ctx))
	if err != nil {
		return err
	}

	return nil
}

func (p *Provider) deleteInstance(ctx context.Context, inst *instance.Server) error {
	err := p.haltInstance(ctx, inst)
	if err != nil {
		return err
	}

	api := instance.NewAPI(p.client)

	ips := inst.PublicIPs
	volumes := inst.Volumes

	err = api.DeleteServer(&instance.DeleteServerRequest{
		Zone:     inst.Zone,
		ServerID: inst.ID,
	}, scw.WithContext(ctx))

	if err != nil {
		return err
	}

	var collectedErrs error
	for _, ip := range ips {
		err = p.deleteIP(ctx, inst.Zone, ip.ID)
		collectedErrs = combineErrors(collectedErrs, err)
	}

	for _, volume := range volumes {
		if volume.VolumeType == instance.VolumeServerVolumeTypeSbsVolume {
			err = p.deleteVolume(ctx, inst.Zone, volume.ID)
			collectedErrs = combineErrors(collectedErrs, err)
		}
	}

	return collectedErrs
}

func (p *Provider) bootInstance(ctx context.Context, inst *instance.Server) (*instance.ServerActionResponse, error) {
	api := instance.NewAPI(p.client)

	return api.ServerAction(&instance.ServerActionRequest{
		Zone:     inst.Zone,
		ServerID: inst.ID,
		Action:   instance.ServerActionPoweron,
	}, scw.WithContext(ctx))
}

func (p *Provider) haltInstance(ctx context.Context, inst *instance.Server) error {
	api := instance.NewAPI(p.client)

	return api.ServerActionAndWait(&instance.ServerActionAndWaitRequest{
		Zone:     inst.Zone,
		ServerID: inst.ID,
		Action:   instance.ServerActionPoweroff,
	}, scw.WithContext(ctx))
}

func (p *Provider) resolveZones() error {
	if p.region != nil {
		if !p.region.Exists() {
			return fmt.Errorf("%w: %s", ErrInvalidRegion, p.region.String())
		}

		p.zones = p.region.GetZones()

		return nil
	}

	if len(p.zones) == 0 {
		return ErrRegionOrZoneNotSet
	}

	for _, zone := range p.zones {
		if !zone.Exists() {
			return fmt.Errorf("%w: %s", ErrInvalidZone, zone.String())
		}
	}

	return nil
}
