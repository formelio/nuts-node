package cmd

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
)

func Test_rootCmd(t *testing.T) {
	t.Run("start in server mode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoServer := core.NewMockEchoServer(ctrl)
		echoServer.EXPECT().GET(gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().POST(gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().PUT(gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().Start(gomock.Any())
		echoCreator = func() core.EchoServer {
			return echoServer
		}
		testDirectory := io.TestDirectory(t)
		os.Setenv("NUTS_NETWORK_DATABASEFILE", path.Join(testDirectory, "network.db"))
		os.Setenv("NUTS_VDR_DATADIR", path.Join(testDirectory, "vdr"))
		os.Setenv("NUTS_CRYPTO_FSPATH", path.Join(testDirectory, "crypto"))
		os.Args = []string{"nuts"}
		Execute()
	})
	t.Run("start in CLI mode", func(t *testing.T) {
		var routesCalled = false
		core.RegisterEngine(&core.Engine{
			Routes: func(router core.EchoRouter) {
				routesCalled = true
			},
		})
		os.Setenv("NUTS_MODE", core.GlobalCLIMode)
		defer os.Unsetenv("NUTS_MODE")
		assert.NoError(t, CreateCommand().Execute())
		assert.False(t, routesCalled, "engine.Routes was called")
	})

}
