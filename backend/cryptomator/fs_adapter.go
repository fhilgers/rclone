package cryptomator

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/object"
)

type VaultFs struct {
  ctx context.Context
  f fs.Fs
}

func (f *VaultFs) Open(name string) (io.ReadCloser, error) {
  obj, err := f.f.NewObject(f.ctx, name)
  if err != nil {
    return nil, err
  }

  return obj.Open(f.ctx)
}

type wrapPipeWriter struct {
  *io.PipeWriter

  chanErr chan(error)
}

func (w *wrapPipeWriter) Close() error {
  err := w.PipeWriter.Close()
  if err != nil {
    return err
  }

  x := <- w.chanErr
  return x
  //return nil
}

func (f *VaultFs) Create(name string) (io.WriteCloser, error) {
  if b, err := fs.FileExists(f.ctx, f.f, name); b {
    return nil, fmt.Errorf("file exists: %s", name)
  } else if err != nil {
    return nil, err
  }

  pipeReader, pipeWriter := io.Pipe()

  info := object.NewStaticObjectInfo(name, time.Now(), -1, true, nil, f.f)

  chanErr := make(chan(error))
  go func() {
    _, err := f.f.Put(f.ctx, pipeReader, info)
    chanErr <- err
  }()

  return &wrapPipeWriter{
    PipeWriter: pipeWriter,
    chanErr: chanErr,
  }, nil
}

func (f *VaultFs) RemoveDir(name string) error {
  return f.f.Rmdir(f.ctx, name)
}

func (f *VaultFs) RemoveFile(name string) error {
  obj, err := f.f.NewObject(f.ctx, name)
  if err != nil {
    return err
  }

  return obj.Remove(f.ctx)
}

func (f *VaultFs) MkdirAll(name string) error {
  return f.f.Mkdir(f.ctx, name)
}
