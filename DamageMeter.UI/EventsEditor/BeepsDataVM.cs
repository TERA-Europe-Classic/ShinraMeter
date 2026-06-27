using Data.Actions.Notify.SoundElements;
using System.Windows.Input;
using Nostrum;
using System.Windows.Threading;

namespace DamageMeter.UI
{
    public class BeepsDataVM : BaseSoundVM
    {
        private readonly Beeps _beeps;
        public SynchronizedObservableCollection<BeepVM> Beeps { get; }

        public ICommand AddBeepCommand { get; }

        public BeepsDataVM(Beeps beeps)
        {
            _beeps = beeps;
            Beeps = new SynchronizedObservableCollection<BeepVM>(Dispatcher.CurrentDispatcher);
            BeepVM.DeleteBeepEvent += OnDeleteBeepEvent;

            beeps.BeepList.ForEach(b => Beeps.Add(new BeepVM(b)));

            AddBeepCommand = new RelayCommand(_ =>
            {
                var beep = new Beep(200, 500);
                _beeps.BeepList.Add(beep);
                Beeps.Add(new BeepVM(beep));
            });
        }

        private void OnDeleteBeepEvent(BeepVM obj)
        {
            _beeps.BeepList.Remove(obj.Beep);
            Beeps.Remove(obj);
        }
    }
}
