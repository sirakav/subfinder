package passive

import (
	"fmt"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/projectdiscovery/gologger"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"github.com/sirakav/subfinder/v2/pkg/subscraping"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/alienvault"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/anubis"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/bevigil"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/binaryedge"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/bufferover"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/builtwith"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/c99"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/censys"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/certspotter"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/chaos"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/chinaz"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/commoncrawl"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/crtsh"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/digitorus"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/dnsdb"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/dnsdumpster"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/dnsrepo"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/facebook"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/fofa"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/fullhunt"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/github"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/hackertarget"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/hunter"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/intelx"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/leakix"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/netlas"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/passivetotal"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/quake"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/rapiddns"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/redhuntlabs"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/robtex"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/securitytrails"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/shodan"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/sitedossier"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/threatbook"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/virustotal"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/waybackarchive"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/whoisxmlapi"
	"github.com/sirakav/subfinder/v2/pkg/subscraping/sources/zoomeyeapi"
)

var AllSources = [...]subscraping.Source{
	&alienvault.Source{},
	&anubis.Source{},
	&bevigil.Source{},
	&binaryedge.Source{},
	&bufferover.Source{},
	&c99.Source{},
	&censys.Source{},
	&certspotter.Source{},
	&chaos.Source{},
	&chinaz.Source{},
	&commoncrawl.Source{},
	&crtsh.Source{},
	&digitorus.Source{},
	&dnsdb.Source{},
	&dnsdumpster.Source{},
	&dnsrepo.Source{},
	&fofa.Source{},
	&fullhunt.Source{},
	&github.Source{},
	&hackertarget.Source{},
	&hunter.Source{},
	&intelx.Source{},
	&netlas.Source{},
	&leakix.Source{},
	&passivetotal.Source{},
	&quake.Source{},
	&rapiddns.Source{},
	&redhuntlabs.Source{},
	// &riddler.Source{}, // failing due to cloudfront protection
	&robtex.Source{},
	&securitytrails.Source{},
	&shodan.Source{},
	&sitedossier.Source{},
	&threatbook.Source{},
	&virustotal.Source{},
	&waybackarchive.Source{},
	&whoisxmlapi.Source{},
	&zoomeyeapi.Source{},
	&facebook.Source{},
	// &threatminer.Source{}, // failing  api
	// &reconcloud.Source{}, // failing due to cloudflare bot protection
	&builtwith.Source{},
}

var sourceWarnings = mapsutil.NewSyncLockMap[string, string](
	mapsutil.WithMap(mapsutil.Map[string, string]{
		"passivetotal": "New API credentials for PassiveTotal can't be generated, but existing user account credentials are still functional. Please ensure your integrations are using valid credentials.",
	}))

var NameSourceMap = make(map[string]subscraping.Source, len(AllSources))

func init() {
	for _, currentSource := range AllSources {
		NameSourceMap[strings.ToLower(currentSource.Name())] = currentSource
	}
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources []subscraping.Source
}

// New creates a new agent for passive subdomain discovery
func New(sourceNames, excludedSourceNames []string, useAllSources, useSourcesSupportingRecurse bool) *Agent {
	sources := make(map[string]subscraping.Source, len(AllSources))

	if useAllSources {
		maps.Copy(sources, NameSourceMap)
	} else {
		if len(sourceNames) > 0 {
			for _, source := range sourceNames {
				if NameSourceMap[source] == nil {
					gologger.Fatal().Msgf("There is no source with the name: %s", source)
				} else {
					sources[source] = NameSourceMap[source]
				}
			}
		} else {
			for _, currentSource := range AllSources {
				if currentSource.IsDefault() {
					sources[currentSource.Name()] = currentSource
				}
			}
		}
	}

	if len(excludedSourceNames) > 0 {
		for _, sourceName := range excludedSourceNames {
			delete(sources, sourceName)
		}
	}

	if useSourcesSupportingRecurse {
		for sourceName, source := range sources {
			if !source.HasRecursiveSupport() {
				delete(sources, sourceName)
			}
		}
	}

	gologger.Debug().Msgf(fmt.Sprintf("Selected source(s) for this search: %s", strings.Join(maps.Keys(sources), ", ")))

	for _, currentSource := range sources {
		if warning, ok := sourceWarnings.Get(strings.ToLower(currentSource.Name())); ok {
			gologger.Warning().Msg(warning)
		}
	}

	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: maps.Values(sources)}

	return agent
}
