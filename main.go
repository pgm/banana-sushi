package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"log"
	"time"

	"github.com/gorilla/mux"
)

const DefaultUpstreamFlushInterval = time.Second

type Upstream struct {
	Timeout               *time.Duration
	FlushInterval         *time.Duration
	InsecureSkipTLSVerify bool
	PassHostHeader        bool
}

// banana bunny eating banana sushi

type ErrorHandler func(http.ResponseWriter, *http.Request, error)

func newProxy(target *url.URL, upstream *Upstream, errorHandler ErrorHandler) http.Handler {
	// proxy code
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Inherit default transport options from Go's stdlib
	transport := http.DefaultTransport.(*http.Transport).Clone()

	// Change default duration for waiting for an upstream response
	if upstream.Timeout != nil {
		transport.ResponseHeaderTimeout = *upstream.Timeout
	}

	// Configure options on the SingleHostReverseProxy
	if upstream.FlushInterval != nil {
		proxy.FlushInterval = *upstream.FlushInterval
	} else {
		proxy.FlushInterval = DefaultUpstreamFlushInterval
	}

	// InsecureSkipVerify is a configurable option we allow
	/* #nosec G402 */
	if upstream.InsecureSkipTLSVerify {
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	// Ensure we always pass the original request path
	setProxyDirector(proxy)

	if !upstream.PassHostHeader {
		setProxyUpstreamHostHeader(proxy, target)
	}

	// Set the error handler so that upstream connection failures render the
	// error page instead of sending a empty response
	if errorHandler != nil {
		proxy.ErrorHandler = errorHandler
	}

	// Apply the customized transport to our proxy before returning it
	proxy.Transport = transport

	return proxy
}

// setProxyDirector sets the proxy.Director so that request URIs are escaped
// when proxying to usptream servers.
func setProxyDirector(proxy *httputil.ReverseProxy) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
		req.URL.ForceQuery = false
	}
}

// setProxyUpstreamHostHeader sets the proxy.Director so that upstream requests
// receive a host header matching the target URL.
func setProxyUpstreamHostHeader(proxy *httputil.ReverseProxy, target *url.URL) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = target.Host
	}
}

func createProxyHandler(target *url.URL, upstream *Upstream, errorHandler ErrorHandler) func(w http.ResponseWriter, r *http.Request) {

	proxyHandler := func(w http.ResponseWriter, r *http.Request) {

		handler := newProxy(target, upstream, errorHandler)

		handler.ServeHTTP(w, r)
	}

	return proxyHandler
}

type ControllerApp struct {
	Services *ServiceManager
	Router   *mux.Router
}

func (c *ControllerApp) ListServices(w http.ResponseWriter, req *http.Request) {
	serviceNames := c.Services.GetServices()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<html><body><ul>")
	for _, name := range serviceNames {
		fmt.Fprintf(w, "<li><a href=\"/banana-sushi/%s\">%s</a></li>", name, name)
	}
	fmt.Fprintf(w, "</ul></body></html>")
}

func (c *ControllerApp) GetServiceStatus(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	service := c.Services.GetServiceState(vars["service"])

	if service == nil {
		w.WriteHeader(http.StatusNotFound)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>Status: %s ", StatusNames[service.Status])
		if service.Status == Stopped {
			fmt.Fprintf(w, "<form method='POST' action='/banana-sushi/%s/start'><input type='submit' value='start'></form>", service.Name)
		} else {
			fmt.Fprintf(w, "<form method='POST' action='/banana-sushi/%s/stop'><input type='submit' value='stop'></form>", service.Name)
		}
		fmt.Fprintf(w, "</body></html>")
	}
}

func (c *ControllerApp) StartService(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	service := vars["service"]
	c.Services.Start(service)

	target, _ := c.Router.Get("ServiceStatus").URL("service", service)
	http.Redirect(w, req, target.String(), http.StatusSeeOther)
}

func (c *ControllerApp) StopService(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	service := vars["service"]
	c.Services.Stop(service)

	target, _ := c.Router.Get("ServiceStatus").URL("service", service)
	http.Redirect(w, req, target.String(), http.StatusSeeOther)
}

func main() {
	sm := NewServiceManager([]*ServiceConfig{
		{
			Name: "portal",
			Start: func() (string, error) {
				time.Sleep(2 * time.Second)
				return "", nil
			},
			Stop: func() error {
				time.Sleep(2 * time.Second)
				return nil
			}}})

	app := &ControllerApp{Services: sm}

	target, err := url.Parse("https://depmap.org")
	if err != nil {
		panic(err)
	}
	timeout := time.Second * 30

	errorHandler := func(w http.ResponseWriter, req *http.Request, err error) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>error: %s</body></html", err)
	}

	upstream := &Upstream{
		Timeout:               &timeout,
		FlushInterval:         nil,
		InsecureSkipTLSVerify: false,
		PassHostHeader:        false}

	r := mux.NewRouter()
	app.Router = r

	r.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		target, err := r.Get("Services").URL()
		if err != nil {
			panic(err)
		}
		http.Redirect(w, req, target.String(), http.StatusSeeOther)
	})

	r.Path("/banana-sushi").HandlerFunc(app.ListServices).Name("Services")
	r.Path("/banana-sushi/{service}").HandlerFunc(app.GetServiceStatus).Name("ServiceStatus")
	r.Path("/banana-sushi/{service}/start").Methods("POST").HandlerFunc(app.StartService)
	r.Path("/banana-sushi/{service}/stop").Methods("POST").HandlerFunc(app.StopService)

	r.PathPrefix("/portal/").HandlerFunc(createProxyHandler(target, upstream, errorHandler))

	// staticDir := "."
	// r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	//	http.Handle("/", r)

	srv := &http.Server{
		Handler: r,
		Addr:    "127.0.0.1:8099",
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

type ServiceStatus int

const (
	Invalid ServiceStatus = iota
	Stopped
	Starting
	Running
	Stopping
)

var StatusNames = map[ServiceStatus]string{
	Invalid:  "Invalid",
	Stopped:  "Stopped",
	Starting: "Starting",
	Running:  "Running",
	Stopping: "Stopping"}

type ServiceConfig struct {
	Name  string
	Start func() (string, error) // blocking method which starts service
	Stop  func() error           // blocking method which stops service
}

type ServiceState struct {
	Name    string
	Status  ServiceStatus
	Address string
}

type ServiceFullState struct {
	State ServiceState
	Start func() (string, error)
	Stop  func() error
}

type Message interface{}

type GetServicesMsg struct {
	response chan []string
}

type GetServiceMsg struct {
	name     string
	response chan *ServiceState
}

type ServiceStartedMsg struct {
	name    string
	address string
}

type ServiceStoppedMsg struct {
	name string
}

type ServiceStopMsg struct {
	name string
}

type ServiceStartMsg struct {
	name string
}

/////////////

type ServiceManager struct {
	mailbox chan Message
}

func serviceManagerActor(serviceList []*ServiceConfig, mailbox chan Message) {
	services := make(map[string]*ServiceFullState)

	for _, service := range serviceList {
		services[service.Name] = &ServiceFullState{
			State: ServiceState{Name: service.Name, Status: Stopped, Address: ""},
			Start: service.Start,
			Stop:  service.Stop}
	}

	getServiceNames := func() []string {
		names := make([]string, len(services))
		i := 0
		for name := range services {
			names[i] = name
			i++
		}
		return names
	}

	start := func(service *ServiceFullState) {
		address, err := service.Start() // blocks until complete
		if err != nil {
			log.Printf("Failed to start: %s", err)
			mailbox <- &ServiceStoppedMsg{service.State.Name}
		} else {
			mailbox <- &ServiceStartedMsg{service.State.Name, address}
		}
	}

	stop := func(service *ServiceFullState) {
		err := service.Stop() // blocks until complete
		if err != nil {
			log.Printf("Failed to stop: %s. Unclear what state it's in.", err)
		} else {
			mailbox <- &ServiceStoppedMsg{service.State.Name}
		}
	}

	for {
		msg := <-mailbox
		switch tmsg := msg.(type) {
		case *GetServiceMsg:
			service, ok := services[tmsg.name]
			if ok {
				copy := service.State
				tmsg.response <- &copy
			} else {
				tmsg.response <- nil
			}
			close(tmsg.response)

		case *GetServicesMsg:
			tmsg.response <- getServiceNames()
			close(tmsg.response)

		case *ServiceStartMsg:
			service, ok := services[tmsg.name]
			if ok {
				service.State.Status = Starting
				go start(service)
			} else {
				log.Printf("Unknown service: %s", tmsg.name)
			}

		case *ServiceStartedMsg:
			service, ok := services[tmsg.name]
			if ok {
				service.State.Status = Running
				service.State.Address = tmsg.address
			} else {
				log.Printf("Unknown service: %s", tmsg.name)
			}

		case *ServiceStopMsg:
			service, ok := services[tmsg.name]
			if ok {
				service.State.Status = Stopping
				go stop(service)
			} else {
				log.Printf("Unknown service: %s", tmsg.name)
			}

		case *ServiceStoppedMsg:
			service, ok := services[tmsg.name]
			if ok {
				service.State.Status = Stopped
				service.State.Address = ""
			} else {
				log.Printf("Unknown service: %s", tmsg.name)
			}

		default:
			log.Fatalf("unknown msg: %s", msg)
		}
	}
}

func NewServiceManager(serviceList []*ServiceConfig) *ServiceManager {
	mailbox := make(chan Message)

	go serviceManagerActor(serviceList, mailbox)

	return &ServiceManager{mailbox: mailbox}
}

func (m *ServiceManager) GetServices() []string {
	response := make(chan []string)

	m.mailbox <- &GetServicesMsg{response: response}

	return <-response
}

func (m *ServiceManager) GetServiceState(name string) *ServiceState {
	response := make(chan *ServiceState)

	m.mailbox <- &GetServiceMsg{response: response, name: name}

	return <-response
}

func (m *ServiceManager) Start(name string) {
	m.mailbox <- &ServiceStartMsg{name: name}
}

func (m *ServiceManager) Stop(name string) {
	m.mailbox <- &ServiceStopMsg{name: name}
}
